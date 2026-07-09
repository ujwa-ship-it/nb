import os
import re
import hmac
import secrets
import time
import math
import asyncio
import logging
import io
from pymongo.errors import DuplicateKeyError, OperationFailure
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from typing import Optional, AsyncIterator

from fastapi import FastAPI, Request, HTTPException, Depends, Response, Query
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pyrogram import Client, errors
from pyrogram.errors import FloodWait
# FileReferenceExpired is not available in every pyrogram version/fork — import defensively.
try:
    from pyrogram.errors import FileReferenceExpired
except ImportError:  # pragma: no cover
    class FileReferenceExpired(Exception):
        """Fallback sentinel — never raised by pyrogram if the real one is missing."""
        pass
try:
    from starlette.exceptions import ClientDisconnect
except ImportError:
    # Starlette 0.36.0+ moved it
    try:
        from starlette._exception import ClientDisconnect
    except ImportError:
        # Fallback for future versions
        class ClientDisconnect(Exception):
            pass


class StreamAbort(Exception):
    """Raised to cleanly abort a streaming response without ugly Uvicorn tracebacks.

    Distinct from ClientDisconnect (which means the *client* hung up) — this is used
    when the *server* wants to abort the stream (e.g. file_id unrecoverable).
    """
    pass

from bson import ObjectId
from bson.errors import InvalidId
import bcrypt
from dotenv import load_dotenv

load_dotenv()

# -------------------------------------------------------------------
# Logging & Config
# -------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
log = logging.getLogger("nexstream")
logging.getLogger("pyrogram").setLevel(logging.WARNING)


def _get_env_or_raise(key: str) -> str:
    v = os.getenv(key)
    if v is None or v == "":
        raise SystemExit(f"❌ Missing required environment variable: {key}")
    return v


MONGO_URL = _get_env_or_raise("MONGO_URL")
BOT_TOKEN = _get_env_or_raise("BOT_TOKEN")
TELEGRAM_API_ID = int(_get_env_or_raise("TELEGRAM_API_ID"))
TELEGRAM_API_HASH = _get_env_or_raise("TELEGRAM_API_HASH")
BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

SESSION_STRING = os.getenv("SESSION_STRING", "").strip()

STREAM_SECRET = os.getenv("STREAM_SECRET") or secrets.token_hex(32)
# Pyrogram's stream_media() uses a HARDCODED 1 MiB internal chunk size
# (set in Client.get_file() at pyrogram/client.py). It is NOT configurable
# via stream_media()'s public API (which only accepts message/limit/offset).
# CHUNK_SIZE must match this value exactly, otherwise Range-request byte
# offsets are computed against the wrong chunk boundary and the video plays
# from the wrong position / seek breaks.
CHUNK_SIZE = 1024 * 1024  # 1 MB — matches pyrogram's internal chunk size

MAX_CONCURRENT_STREAMS = int(os.getenv("MAX_CONCURRENT_STREAMS", "4"))
MAX_THUMB_CACHE = int(os.getenv("MAX_THUMB_CACHE", "200"))

# -------------------------------------------------------------------
# Database
# -------------------------------------------------------------------
mongo = AsyncIOMotorClient(MONGO_URL, tz_aware=True, serverSelectionTimeoutMS=10000)
db = mongo.nexstream
videos_col = db.videos
users_col = db.users

# -------------------------------------------------------------------
# MTProto Clients
# -------------------------------------------------------------------
stream_client: Optional[Client] = None
bot_app: Optional[Client] = None
# Track which clients actually started successfully — a Client object exists
# even if .start() raised, so checking `is not None` is not enough.
_clients_started: dict = {"stream": False, "bot": False}

_stream_semaphore = asyncio.Semaphore(MAX_CONCURRENT_STREAMS)


class BoundedCache:
    def __init__(self, max_size: int = MAX_THUMB_CACHE):
        self._max = max_size
        self._data: dict[str, bytes] = {}
        self._lock = asyncio.Lock()

    def get(self, key: str) -> Optional[bytes]:
        return self._data.get(key)

    async def set(self, key: str, value: bytes):
        async with self._lock:
            if key in self._data:
                self._data.pop(key)
            self._data[key] = value
            while len(self._data) > self._max:
                oldest = next(iter(self._data))
                self._data.pop(oldest, None)


thumb_cache = BoundedCache(MAX_THUMB_CACHE)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def validate_object_id(vid: str) -> ObjectId:
    try:
        return ObjectId(vid)
    except (InvalidId, TypeError):
        raise HTTPException(404, "Not found")


def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_pw(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def is_valid_email(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def escape_regex(text: str) -> str:
    return re.escape(text)


async def get_token_from_request(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return request.query_params.get("token")


async def auth(request: Request) -> dict:
    token = await get_token_from_request(request)
    if not token:
        raise HTTPException(401, "Not logged in")
    user = await users_col.find_one({"token": token})
    if not user:
        raise HTTPException(401, "Invalid token")

    expires_at = user.get("expires_at")
    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(401, "Token expired")
    return user


# -------------------------------------------------------------------
# Lifespan
# -------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global stream_client, bot_app

    bot_app = Client(
        "server_bot_session",
        api_id=TELEGRAM_API_ID,
        api_hash=TELEGRAM_API_HASH,
        bot_token=BOT_TOKEN,
        in_memory=False,
        no_updates=True,
    )
    try:
        await bot_app.start()
        _clients_started["bot"] = True
    except FloodWait as e:
        log.error(f"Bot FloodWait at startup: sleeping {e.value}s")
        await asyncio.sleep(e.value + 1)
        try:
            await bot_app.start()
            _clients_started["bot"] = True
        except Exception as e:
            log.error(f"Bot failed to start after FloodWait: {e}")
            raise
    log.info("Bot session started.")

    if SESSION_STRING:
        stream_client = Client(
            "server_user_session",
            api_id=TELEGRAM_API_ID,
            api_hash=TELEGRAM_API_HASH,
            session_string=SESSION_STRING,
            in_memory=True,
            no_updates=True,
        )
        try:
            await stream_client.start()
            _clients_started["stream"] = True
            log.info("✅ User session started — streaming will use user session (no FloodWait).")
        except FloodWait as e:
            log.error(f"User session FloodWait: {e.value}s — falling back to bot.")
            stream_client = None
        except Exception as e:
            log.error(f"User session failed: {e} — falling back to bot.")
            stream_client = None
    else:
        log.warning(
            "⚠️  No SESSION_STRING provided. Streaming via bot session — "
            "you WILL hit auth.ExportAuthorization FloodWait under load."
        )

    await ensure_indexes()
    log.info("NexStream API initialized.")
    yield

    for c in (stream_client, bot_app):
        if c is not None:
            try:
                await c.stop()
            except Exception:
                pass


web = FastAPI(lifespan=lifespan, docs_url="/docs", redoc_url=None)

web.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "https://nb-orwg.onrender.com",
    ],
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Global exception handler — catches unhandled exceptions (e.g. pymongo
# WriteError, network errors) and returns a proper JSON 500 response. Without
# this, an unhandled exception inside an endpoint produces a bare 500 with no
# CORS headers, which the browser then blocks with a misleading "CORS error"
# instead of showing the real problem.
# ---------------------------------------------------------------------------
@web.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Re-raise HTTPException so FastAPI's built-in handler still produces the
    # correct status code + detail body for those.
    if isinstance(exc, HTTPException):
        raise exc
    # StreamAbort should never reach here (stream_generator catches it),
    # but handle it defensively to avoid returning a 500 JSON when response
    # headers have already been sent.
    if isinstance(exc, StreamAbort):
        log.warning(f"StreamAbort leaked to global handler on {request.url.path}: {exc}")
        return Response(status_code=204, content=b"")
    log.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {type(exc).__name__}"},
    )


async def ensure_indexes():
    try:
        # Safely drop old non-unique index to prevent IndexKeySpecsConflict
        try:
            existing_indexes = await videos_col.index_information()
            if "channel_id_1_message_id_1" in existing_indexes:
                if not existing_indexes["channel_id_1_message_id_1"].get("unique", False):
                    await videos_col.drop_index("channel_id_1_message_id_1")
        except OperationFailure:
            pass

        await videos_col.create_index("file_unique_id", unique=True, sparse=True)
        await videos_col.create_index([("channel_id", 1), ("message_id", 1)], unique=True, name="channel_message_unique")
        await videos_col.create_index("type")
        await videos_col.create_index([("title", "text")])
        await videos_col.create_index("date")
        await users_col.create_index("token")
        await users_col.create_index("email", unique=True, sparse=True)
    except Exception as e:
        log.warning("Could not ensure indexes: %s", e)


def format_video_doc(d: dict) -> Optional[dict]:
    if d is None:
        return None
    d = dict(d)
    d["id"] = str(d.pop("_id"))
    base = BASE_URL or ""
    d["thumb_url"] = d.get("thumb_url") or (
        f"{base}/api/thumb/{d['thumb_file_id']}" if d.get("thumb_file_id") else ""
    )
    if not d.get("genres"):
        d["genres"] = []
    if d.get("type") not in ("movie", "game"):
        d["type"] = "movie"
    return d


def _get_stream_client() -> Client:
    if stream_client is not None and _clients_started["stream"]:
        return stream_client
    if bot_app is not None and _clients_started["bot"]:
        return bot_app
    raise HTTPException(503, "Streaming service not available")


# -------------------------------------------------------------------
# AUTH ROUTES
# -------------------------------------------------------------------
@web.post("/api/auth/register")
async def register(data: dict):
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    pw = str(data.get("password", ""))
    if not name or not is_valid_email(email) or len(pw) < 6:
        raise HTTPException(400, "Invalid input")

    token = secrets.token_hex(32)
    # get_event_loop() is deprecated in 3.10+ inside async code; use the running loop.
    loop = asyncio.get_running_loop()
    hashed = await loop.run_in_executor(None, hash_pw, pw)
    expires = datetime.now(timezone.utc) + timedelta(days=30)

    try:
        await users_col.insert_one({
            "name": name, "email": email, "password": hashed,
            "token": token, "expires_at": expires, "my_list": [], "history": [],
            "created_at": datetime.now(timezone.utc),
        })
    except DuplicateKeyError:
        raise HTTPException(400, "Email already exists")
    return {"token": token, "name": name, "email": email}


@web.post("/api/auth/login")
async def login(data: dict):
    email = str(data.get("email", "")).strip().lower()
    pw = str(data.get("password", ""))
    user = await users_col.find_one({"email": email})
    if not user:
        raise HTTPException(401, "Wrong email or password")
    loop = asyncio.get_running_loop()
    ok = await loop.run_in_executor(None, verify_pw, pw, user["password"])
    if not ok:
        raise HTTPException(401, "Wrong email or password")

    token = secrets.token_hex(32)
    expires = datetime.now(timezone.utc) + timedelta(days=30)
    await users_col.update_one({"_id": user["_id"]}, {"$set": {"token": token, "expires_at": expires}})
    return {"token": token, "name": user["name"], "email": user["email"]}


@web.get("/api/auth/me")
async def me(user: dict = Depends(auth)):
    return {"name": user["name"], "email": user["email"]}


@web.post("/api/auth/logout")
async def logout(user: dict = Depends(auth)):
    """Invalidate the current session token server-side.

    Previously the client just cleared localStorage — the token stayed valid
    for 30 days on the server, so anyone who had sniffed it could keep using
    the account.
    """
    await users_col.update_one(
        {"_id": user["_id"]},
        {"$unset": {"token": "", "expires_at": ""}},
    )
    return {"ok": True}


# -------------------------------------------------------------------
# MOVIES / GAMES / SEARCH
# -------------------------------------------------------------------
def _apply_genre_filter(q: dict, genre: str):
    if genre and genre.lower() != "all":
        q["genres"] = {"$in": [genre]}


@web.get("/api/movies")
async def get_movies(page: int = 1, limit: int = 20, genre: str = ""):
    page = max(1, page)
    limit = max(1, min(limit, 100))
    q: dict = {"type": "movie"}
    _apply_genre_filter(q, genre)
    cursor = videos_col.find(q).sort("date", -1).skip((page - 1) * limit).limit(limit)
    docs = await cursor.to_list(length=limit)
    total = await videos_col.count_documents(q)
    return {"total": total, "page": page, "data": [format_video_doc(d) for d in docs]}


@web.get("/api/games")
async def get_games(page: int = 1, limit: int = 20, genre: str = ""):
    page = max(1, page)
    limit = max(1, min(limit, 100))
    q: dict = {"type": "game"}
    _apply_genre_filter(q, genre)
    cursor = videos_col.find(q).sort("date", -1).skip((page - 1) * limit).limit(limit)
    docs = await cursor.to_list(length=limit)
    total = await videos_col.count_documents(q)
    return {"total": total, "page": page, "data": [format_video_doc(d) for d in docs]}


@web.get("/api/movies/{vid}")
async def get_movie(vid: str):
    doc = await videos_col.find_one({"_id": validate_object_id(vid)})
    if not doc:
        raise HTTPException(404, "Not found")
    return format_video_doc(doc)


@web.get("/api/search")
async def search(q: str = "", page: int = 1, limit: int = 20):
    if not q or len(q) < 2:
        return {"total": 0, "page": page, "data": []}
    page = max(1, page)
    limit = max(1, min(limit, 100))
    q_filter = {"title": {"$regex": escape_regex(q), "$options": "i"}}
    cursor = videos_col.find(q_filter).sort("date", -1).skip((page - 1) * limit).limit(limit)
    docs = await cursor.to_list(length=limit)
    total = await videos_col.count_documents(q_filter)
    return {"total": total, "page": page, "data": [format_video_doc(d) for d in docs]}


# -------------------------------------------------------------------
# CORE STREAMING LOGIC
# -------------------------------------------------------------------
def _parse_range(range_header: Optional[str], file_size: int):
    """Parse an HTTP `Range: bytes=` header.

    Supports three forms per RFC 7233:
      • bytes=0-1023        → first 1024 bytes
      • bytes=1024-         → from byte 1024 to end
      • bytes=-512          → last 512 bytes (suffix range)
    """
    start = 0
    end = file_size - 1
    if range_header:
        # Suffix range: bytes=-N  →  last N bytes
        m_suffix = re.match(r"bytes=-(\d+)$", range_header)
        if m_suffix:
            n = int(m_suffix.group(1))
            if n == 0:
                raise HTTPException(416, "Requested range not satisfiable")
            start = max(0, file_size - n)
            end = file_size - 1
        else:
            match = re.match(r"bytes=(\d+)-(\d*)", range_header)
            if match:
                start = int(match.group(1))
                if match.group(2):
                    end = min(int(match.group(2)), file_size - 1)
                # else: open-ended range → end stays at file_size - 1
    if start >= file_size:
        raise HTTPException(416, "Requested range not satisfiable")
    return start, end


async def _refresh_file_id(doc: dict) -> str:
    """Fetch fresh file_id from Telegram if it expired."""
    fetch_client = None
    if stream_client is not None and _clients_started["stream"]:
        fetch_client = stream_client
    elif bot_app is not None and _clients_started["bot"]:
        fetch_client = bot_app
    if not fetch_client:
        raise StreamAbort("No MTProto client available to refresh file_id")

    channel_id = doc.get("channel_id")
    message_id = doc.get("message_id")
    if not channel_id or not message_id:
        raise StreamAbort(
            f"Cannot refresh file_id: missing channel_id or message_id "
            f"(channel_id={channel_id!r}, message_id={message_id!r})"
        )

    msg = await fetch_client.get_messages(channel_id, message_id)
    new_file_id = None
    if msg.video:
        new_file_id = msg.video.file_id
    elif msg.document:
        new_file_id = msg.document.file_id

    if not new_file_id:
        raise StreamAbort("Refreshed message has no video/document file_id")

    await videos_col.update_one(
        {"_id": doc["_id"]},
        {"$set": {"file_id": new_file_id, "bot_file_id": new_file_id}}
    )
    log.info("File reference refreshed successfully.")
    return new_file_id


async def _iter_chunks(
    client: Client,
    doc: dict,
    offset: int,
    limit: int,
    request: Request,
) -> AsyncIterator[bytes]:
    current_file_id = doc.get("file_id") or doc.get("bot_file_id")
    refreshed = False
    yielded_any = False

    while True:
        try:
            # stream_media() only accepts (message, limit, offset) — no
            # chunk_size kwarg. The 1 MiB chunk size is hardcoded internally
            # in pyrogram and must match CHUNK_SIZE above.
            async for chunk in client.stream_media(
                current_file_id, limit=limit, offset=offset
            ):
                if await request.is_disconnected():
                    raise ClientDisconnect()
                if chunk:
                    yielded_any = True
                    yield chunk

            # --- Silent FileReferenceExpired detection ---
            # Some pyrogram versions catch FileReferenceExpired *inside*
            # stream_media / get_file and just stop iterating instead of
            # re-raising.  The result: the async-for above ends normally
            # with 0 bytes yielded.  Detect this and attempt a refresh
            # before giving up.
            if not yielded_any and not refreshed:
                log.warning(
                    "Stream yielded 0 bytes — file reference likely expired "
                    "(pyrogram swallowed the error).  Refreshing file_id…"
                )
                try:
                    current_file_id = await _refresh_file_id(doc)
                    refreshed = True
                    continue  # retry with fresh file_id
                except StreamAbort:
                    raise
                except Exception as e:
                    log.error(f"File reference refresh failed: {e}")
                    raise StreamAbort(f"Refresh failed: {e}")

            return  # Completed successfully
        except FileReferenceExpired:
            if refreshed or yielded_any:
                log.error("File reference expired mid-stream or after refresh. Aborting.")
                raise StreamAbort("File reference expired after refresh")
            log.warning("FileReferenceExpired caught explicitly. Fetching fresh file_id...")
            try:
                current_file_id = await _refresh_file_id(doc)
                refreshed = True
                continue
            except StreamAbort:
                raise
            except Exception as e:
                log.error(f"Failed to refresh file reference: {e}")
                raise StreamAbort(f"Refresh failed: {e}")
        except FloodWait as e:
            log.warning(f"FloodWait {e.value}s during stream. Backing off.")
            await asyncio.sleep(e.value + 1)
            continue
        except (ClientDisconnect, StreamAbort):
            raise
        except Exception as e:
            log.warning(f"Stream chunk error: {e}")
            raise StreamAbort(f"Chunk error: {e}")


def build_stream_response(doc: dict, request: Request):
    file_id = doc.get("file_id") or doc.get("bot_file_id")
    if not file_id:
        raise HTTPException(400, "No file_id available for streaming")

    file_size = int(doc.get("file_size", 0) or 0)
    if file_size <= 0:
        raise HTTPException(400, "Invalid file size")

    client = _get_stream_client()

    range_header = request.headers.get("range")
    start, end = _parse_range(range_header, file_size)
    length = end - start + 1

    chunk_offset = start // CHUNK_SIZE
    discard = start % CHUNK_SIZE
    chunk_limit = math.ceil((length + discard) / CHUNK_SIZE)

    async def stream_generator():
        sent = 0
        try:
            async with _stream_semaphore:
                async for chunk in _iter_chunks(client, doc, chunk_offset, chunk_limit, request):
                    if sent == 0 and discard > 0:
                        chunk = chunk[discard:]
                    if not chunk:
                        continue
                    remaining = length - sent
                    if len(chunk) >= remaining:
                        yield chunk[:remaining]
                        sent = length
                        return
                    yield chunk
                    sent += len(chunk)

            # Check for premature end — INSIDE the try block so the
            # StreamAbort below is caught and doesn't leak to ASGI.
            if sent < length:
                log.warning(f"Stream ended prematurely. Sent {sent}, expected {length}")
                raise StreamAbort("Premature end")

        except ClientDisconnect:
            # The client hung up (tab closed, navigated away).  Just stop.
            return
        except StreamAbort as e:
            # Server-side abort (expired ref, chunk error, etc.).
            # Log it and stop cleanly — never let it propagate to ASGI.
            log.info(f"Stream aborted: {e}")
            return
        except Exception as e:
            log.warning(f"Stream aborted unexpectedly: {e}")
            return

    headers = {
        "Accept-Ranges": "bytes",
        "Content-Length": str(length),
        "Cache-Control": "public, max-age=86400",
    }
    status_code = 200
    if range_header:
        headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
        status_code = 206

    return StreamingResponse(
        stream_generator(),
        status_code=status_code,
        media_type=doc.get("mime_type", "video/mp4"),
        headers=headers,
    )


@web.head("/api/stream/{vid}")
async def stream_head(vid: str, user=Depends(auth)):
    doc = await videos_col.find_one({"_id": validate_object_id(vid)})
    if not doc:
        raise HTTPException(404, "Not found")
    return Response(
        status_code=200,
        headers={
            "Content-Length": str(doc.get("file_size", 0)),
            "Accept-Ranges": "bytes",
            "Content-Type": doc.get("mime_type", "video/mp4"),
        },
    )


@web.get("/api/stream/{vid}")
async def stream_video(vid: str, request: Request, user=Depends(auth)):
    doc = await videos_col.find_one({"_id": validate_object_id(vid)})
    if not doc:
        raise HTTPException(404, "Not found")
    return build_stream_response(doc, request)


@web.get("/watch/{message_id}/{file_unique_id}.mp4")
async def watch_hashed(
    message_id: int,
    file_unique_id: str,
    request: Request,
    sig_hash: str = Query("", alias="hash"),
):
    doc = await videos_col.find_one(
        {"message_id": message_id, "file_unique_id": file_unique_id}
    )
    if not doc:
        raise HTTPException(404, "Not found")

    try:
        expiry = int(sig_hash[8:]) if len(sig_hash) > 8 else 0
        sig = sig_hash[:8]
        raw = f"{str(doc['_id'])}:{expiry}"
        expected = hmac.new(
            STREAM_SECRET.encode(), raw.encode(), "sha256"
        ).hexdigest()[:8]
        if not hmac.compare_digest(sig, expected) or time.time() > expiry:
            raise HTTPException(403, "Invalid or expired link")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(403, "Invalid hash")

    return build_stream_response(doc, request)


@web.get("/api/video/{vid}/watch-url")
async def get_watch_url(vid: str, user=Depends(auth)):
    doc = await videos_col.find_one(
        {"_id": validate_object_id(vid)},
        {"message_id": 1, "file_unique_id": 1},
    )
    if not doc:
        raise HTTPException(404, "Not found")
    if not BASE_URL:
        raise HTTPException(500, "PUBLIC_BASE_URL is not configured on the server")
    expiry = int(time.time()) + 3600
    raw = f"{str(doc['_id'])}:{expiry}"
    sig = hmac.new(STREAM_SECRET.encode(), raw.encode(), "sha256").hexdigest()[:8]
    url = f"{BASE_URL}/watch/{doc['message_id']}/{doc['file_unique_id']}.mp4?hash={sig}{expiry}"
    return {"url": url}


# -------------------------------------------------------------------
# THUMBNAILS (With Auto-Refresh)
# -------------------------------------------------------------------
@web.get("/api/thumb/{file_id}")
async def get_thumb(file_id: str):
    if not file_id or len(file_id) < 10:
        raise HTTPException(404, "Not found")

    cached = thumb_cache.get(file_id)
    if cached:
        return Response(content=cached, media_type="image/jpeg")

    if bot_app is None or not _clients_started["bot"]:
        raise HTTPException(503, "Thumbnail service not available")

    async def stream_thumb():
        buffer = io.BytesIO()
        current_file_id = file_id
        refreshed = False

        while True:
            try:
                async for chunk in bot_app.stream_media(current_file_id):
                    if chunk:
                        buffer.write(chunk)
                        yield chunk
                await thumb_cache.set(file_id, buffer.getvalue())
                return
            except FileReferenceExpired:
                if refreshed:
                    log.error("Thumb file reference expired again after refresh.")
                    return
                log.warning("Thumb file reference expired. Refreshing...")
                video_doc = await videos_col.find_one(
                    {"thumb_file_id": file_id}, {"channel_id": 1, "message_id": 1}
                )
                if not video_doc:
                    return
                try:
                    msg = await bot_app.get_messages(video_doc["channel_id"], video_doc["message_id"])
                    new_thumb_id = None
                    if msg.video and msg.video.thumbs:
                        new_thumb_id = max(msg.video.thumbs, key=lambda t: t.width or 0).file_id
                    elif msg.document and msg.document.thumbs:
                        new_thumb_id = max(msg.document.thumbs, key=lambda t: t.width or 0).file_id
                    if new_thumb_id:
                        current_file_id = new_thumb_id
                        await videos_col.update_one(
                            {"_id": video_doc["_id"]},
                            {"$set": {"thumb_file_id": current_file_id}},
                        )
                        refreshed = True
                        continue
                    log.error("Refreshed message has no thumbnail.")
                    return
                except Exception as e:
                    log.error(f"Failed to refresh thumb: {e}")
                    return
            except Exception as e:
                log.error(f"Thumbnail stream error: {e}")
                return

    return StreamingResponse(stream_thumb(), media_type="image/jpeg")


# -------------------------------------------------------------------
# USER LIST / HISTORY
# -------------------------------------------------------------------
def _normalize_ids(ids):
    valid = []
    for i in ids or []:
        try:
            valid.append(ObjectId(i))
        except (InvalidId, TypeError):
            continue
    return valid


@web.get("/api/user/list")
async def get_list(user: dict = Depends(auth)):
    raw_list = user.get("my_list", [])
    valid_ids = _normalize_ids(raw_list)
    docs = await videos_col.find({"_id": {"$in": valid_ids}}).to_list(length=len(valid_ids))
    order = {str(i): idx for idx, i in enumerate(raw_list)}
    docs.sort(key=lambda x: order.get(str(x["_id"]), 9999))
    return [format_video_doc(d) for d in docs]


@web.post("/api/user/list/{vid}")
async def toggle_list(vid: str, data: dict = None, user: dict = Depends(auth)):
    """Add, remove, or toggle a video in the user's My List.

    Body (optional): {"action": "add" | "remove" | "toggle"}
    Default is "toggle" for backwards compatibility.

    The previous implementation always toggled based on server state, which
    raced with the client's optimistic update: two rapid clicks could leave
    client and server out of sync. Accepting an explicit action makes each
    request idempotent.
    """
    validate_object_id(vid)
    if not await videos_col.find_one({"_id": ObjectId(vid)}, {"_id": 1}):
        raise HTTPException(404, "Not found")

    action = (data or {}).get("action", "toggle").lower()
    if action == "add":
        await users_col.update_one({"_id": user["_id"]}, {"$addToSet": {"my_list": vid}})
        return {"added": True}
    if action == "remove":
        await users_col.update_one({"_id": user["_id"]}, {"$pull": {"my_list": vid}})
        return {"added": False}

    # toggle (legacy)
    if vid in user.get("my_list", []):
        await users_col.update_one({"_id": user["_id"]}, {"$pull": {"my_list": vid}})
        return {"added": False}
    await users_col.update_one({"_id": user["_id"]}, {"$addToSet": {"my_list": vid}})
    return {"added": True}


@web.get("/api/user/history")
async def get_history(user: dict = Depends(auth)):
    raw_hist = user.get("history", [])
    valid_ids = _normalize_ids(raw_hist)
    docs = await videos_col.find({"_id": {"$in": valid_ids}}).to_list(length=len(valid_ids))
    # raw_hist is stored oldest→newest (we $push on each watch). Reverse it so
    # the most recently watched video sorts to index 0, matching the client.
    order = {str(i): idx for idx, i in enumerate(reversed(raw_hist))}
    docs.sort(key=lambda x: order.get(str(x["_id"]), 9999))
    return [format_video_doc(d) for d in docs]


@web.post("/api/user/history/{vid}")
async def add_history(vid: str, user: dict = Depends(auth)):
    validate_object_id(vid)
    # NOTE: MongoDB forbids combining $pull and $push on the SAME field in a
    # single update document (raises WriteError code 40: "Updating the path
    # 'history' would create a conflict at 'history'"). We must run them as
    # two separate updates. This is still safe — the $pull is idempotent and
    # the $push uses $slice to cap the array at 200 entries. The tiny window
    # between the two updates is acceptable for a watch-history use case.
    await users_col.update_one(
        {"_id": user["_id"]},
        {"$pull": {"history": vid}},
    )
    await users_col.update_one(
        {"_id": user["_id"]},
        {"$push": {"history": {"$each": [vid], "$slice": -200}}},
    )
    return {"ok": True}


@web.delete("/api/user/history")
async def clear_history(user: dict = Depends(auth)):
    await users_col.update_one({"_id": user["_id"]}, {"$set": {"history": []}})
    return {"ok": True}


# -------------------------------------------------------------------
# STATS & HEALTH
# -------------------------------------------------------------------
@web.get("/api/stats")
async def get_stats():
    pipeline = [
        {"$facet": {
            "total": [{"$count": "count"}],
            "movies": [{"$match": {"type": "movie"}}, {"$count": "count"}],
            "games": [{"$match": {"type": "game"}}, {"$count": "count"}],
            "channels": [{"$group": {"_id": "$channel_id"}}],
        }}
    ]
    results = await videos_col.aggregate(pipeline).to_list(length=1)
    res = results[0] if results else {}

    def _c(arr):
        return arr[0]["count"] if arr else 0

    return {
        "total_videos": _c(res.get("total", [])),
        "movies": _c(res.get("movies", [])),
        "games": _c(res.get("games", [])),
        "channels": len(res.get("channels", [])),
    }


@web.get("/api/health")
async def health():
    try:
        count = await videos_col.estimated_document_count()
        return {
            "status": "ok",
            "videos": count,
            "stream_client": "user" if stream_client else ("bot" if bot_app else "none"),
        }
    except Exception as e:
        return JSONResponse({"status": "degraded", "error": str(e)}, status_code=503)


@web.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:web", host="0.0.0.0", port=8000, reload=True)
