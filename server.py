import os
import re
import secrets
import math
import asyncio
import logging
import io
from urllib.parse import quote
from pymongo.errors import DuplicateKeyError, OperationFailure
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from typing import Optional, AsyncIterator

from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.responses import StreamingResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pyrogram import Client, errors
from pyrogram.errors import FloodWait
try:
    from pyrogram.errors import FileReferenceExpired
except ImportError:
    class FileReferenceExpired(Exception):
        pass
try:
    from pyrogram.errors import PeerIdInvalid
except ImportError:
    class PeerIdInvalid(Exception):
        pass
from pyrogram.raw import functions as raw_functions
from pyrogram.raw import types as raw_types
try:
    from starlette.exceptions import ClientDisconnect
except ImportError:
    try:
        from starlette._exception import ClientDisconnect
    except ImportError:
        class ClientDisconnect(Exception):
            pass

class StreamAbort(Exception):
    """Raised to cleanly abort a streaming response."""
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


class _SuppressFileRefExpired(logging.Filter):
    """Filter out FILE_REFERENCE_EXPIRED log entries (handled by our code)."""
    def filter(self, record):
        return "FILE_REFERENCE_EXPIRED" not in record.getMessage()

logging.getLogger("pyrogram.client").addFilter(_SuppressFileRefExpired())


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

CHUNK_SIZE = 1024 * 1024  # 1 MB – must match pyrogram's internal chunk size
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


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename for use in Content-Disposition headers."""
    if not filename:
        return "download"
    # Remove or replace dangerous characters
    filename = re.sub(r'[\\/:*?"<>|\r\n]', '_', filename)
    # Limit length
    if len(filename) > 200:
        name, _, ext = filename.rpartition('.')
        if ext:
            filename = name[:190] + '.' + ext
        else:
            filename = filename[:200]
    return filename


def get_file_extension(mime_type: str, filename: str = "") -> str:
    """Get file extension from mime type or filename."""
    if filename and '.' in filename:
        ext = filename.rsplit('.', 1)[-1]
        if ext and len(ext) <= 5:
            return ext.lower()
    
    mime_to_ext = {
        "video/mp4": "mp4",
        "video/x-matroska": "mkv",
        "video/webm": "webm",
        "video/avi": "avi",
        "video/quicktime": "mov",
        "video/x-flv": "flv",
        "video/x-msvideo": "avi",
        "video/mpeg": "mpeg",
        "video/3gpp": "3gp",
        "audio/mpeg": "mp3",
        "audio/ogg": "ogg",
        "audio/wav": "wav",
        "audio/webm": "weba",
        "application/octet-stream": "bin",
    }
    return mime_to_ext.get(mime_type, "bin")


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
# Backfill channel_access_hash for existing videos
# -------------------------------------------------------------------
async def _backfill_access_hashes():
    """Backfill channel_access_hash for videos synced before sync.py stored it."""
    try:
        pipeline = [
            {"$match": {"channel_access_hash": {"$exists": False}}},
            {"$group": {"_id": "$channel_id"}},
        ]
        channels = await videos_col.aggregate(pipeline).to_list(length=1000)
        if not channels:
            return

        log.info(f"Backfilling access_hash for {len(channels)} channel(s)...")

        for ch_doc in channels:
            channel_id = ch_doc["_id"]
            if not channel_id:
                continue

            access_hash = None
            for client_name, client in [("bot", bot_app), ("stream", stream_client)]:
                if client is None or not _clients_started.get(client_name):
                    continue
                try:
                    peer = await client.resolve_peer(channel_id)
                    if hasattr(peer, "access_hash"):
                        access_hash = peer.access_hash
                        break
                except Exception:
                    continue

            if access_hash is not None:
                await videos_col.update_many(
                    {"channel_id": channel_id, "channel_access_hash": {"$exists": False}},
                    {"$set": {"channel_access_hash": access_hash}}
                )
                log.info(f"  ✅ Backfilled access_hash for channel {channel_id}")
            else:
                log.warning(
                    f"  ⚠️  Could not resolve channel {channel_id} — "
                    f"access_hash will be filled when new messages are synced"
                )
    except Exception as e:
        log.error(f"Backfill task error: {e}")


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
        )
        try:
            await stream_client.start()
            _clients_started["stream"] = True
            log.info("✅ User session started — streaming will use user session.")
        except FloodWait as e:
            log.error(f"User session FloodWait: {e.value}s — falling back to bot.")
            stream_client = None
        except Exception as e:
            log.error(f"User session failed: {e} — falling back to bot.")
            stream_client = None
    else:
        log.warning("⚠️  No SESSION_STRING provided. Streaming via bot session.")

    await ensure_indexes()
    asyncio.create_task(_backfill_access_hashes())

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


@web.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        raise exc
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
        existing_indexes = await videos_col.index_information()
        if "channel_id_1_message_id_1" in existing_indexes:
            if not existing_indexes["channel_id_1_message_id_1"].get("unique", False):
                await videos_col.drop_index("channel_id_1_message_id_1")
        await videos_col.create_index("file_unique_id", unique=True, sparse=True)
        await videos_col.create_index(
            [("channel_id", 1), ("message_id", 1)], unique=True, name="channel_message_unique"
        )
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
        f"{base}/api/thumb/{d['id']}" if d.get("thumb_file_id") else ""
    )
    # Generate permanent Vinnoflow-style URLs
    if d.get("message_id") and d.get("file_unique_id"):
        d["stream_url"] = f"{base}/watch/{d['message_id']}/{d['file_unique_id']}"
        d["download_url"] = f"{base}/download/{d['message_id']}/{d['file_unique_id']}"
    else:
        d["stream_url"] = ""
        d["download_url"] = ""
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
    await users_col.update_one(
        {"_id": user["_id"]},
        {"$set": {"token": token, "expires_at": expires}}
    )
    return {"token": token, "name": user["name"], "email": user["email"]}


@web.get("/api/auth/me")
async def me(user: dict = Depends(auth)):
    return {"name": user["name"], "email": user["email"]}


@web.post("/api/auth/logout")
async def logout(user: dict = Depends(auth)):
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
        q["genres"] = {"$in": [genre.lower()]}


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
# Rating endpoint
# -------------------------------------------------------------------
@web.patch("/api/movies/{vid}/rating")
async def set_rating(vid: str, data: dict, user: dict = Depends(auth)):
    oid = validate_object_id(vid)
    rating = data.get("rating")
    if rating is None:
        raise HTTPException(400, "Missing 'rating' field")
    try:
        rating = float(rating)
    except (TypeError, ValueError):
        raise HTTPException(400, "Rating must be a number")
    if not (0 <= rating <= 10):
        raise HTTPException(400, "Rating must be between 0 and 10")
    result = await videos_col.update_one(
        {"_id": oid},
        {"$set": {"rating": round(rating, 1)}}
    )
    if result.matched_count == 0:
        raise HTTPException(404, "Not found")
    return {"ok": True, "rating": round(rating, 1)}


# -------------------------------------------------------------------
# CORE STREAMING LOGIC — VINNOFLOW / FILETOLINK APPROACH
# -------------------------------------------------------------------
def _parse_range(range_header: Optional[str], file_size: int):
    start = 0
    end = file_size - 1
    if range_header:
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
    if start >= file_size:
        raise HTTPException(416, "Requested range not satisfiable")
    return start, end


async def _fetch_message_fresh(doc: dict):
    """Fetch a message fresh from Telegram — NEVER use stored file_id.

    This is the Vinnoflow/FileToLink approach: on every stream/download request,
    we re-fetch the message from the channel to get a brand-new, valid file_id
    with a fresh file reference. This completely eliminates the file_id expiry
    problem — we never depend on a stored file_id that could be hours old.

    Three-tier fallback for peer resolution:
      1. get_messages() — works if peer is cached in session
      2. resolve_peer() + retry — forces peer caching
      3. Raw MTProto API with stored access_hash — bypasses session cache
    """
    fetch_client = None
    if stream_client is not None and _clients_started["stream"]:
        fetch_client = stream_client
    elif bot_app is not None and _clients_started["bot"]:
        fetch_client = bot_app
    if not fetch_client:
        raise HTTPException(503, "No MTProto client available")

    channel_id = doc.get("channel_id")
    message_id = doc.get("message_id")
    if not channel_id or not message_id:
        raise HTTPException(400, "Missing channel_id or message_id")

    # --- Tier 1: Direct get_messages() ---
    try:
        msg = await fetch_client.get_messages(channel_id, message_id)
        if msg:
            return msg
    except PeerIdInvalid:
        log.warning(f"PeerIdInvalid for channel {channel_id} (tier 1)")
    except Exception as e:
        err_str = str(e).lower()
        if "peer" not in err_str or "invalid" not in err_str:
            log.error(f"get_messages failed (tier 1): {e}")
            raise HTTPException(503, f"Failed to fetch message: {e}")

    # --- Tier 2: resolve_peer() to force caching, then retry ---
    log.info(f"Trying resolve_peer for channel {channel_id} (tier 2)...")
    try:
        await fetch_client.resolve_peer(channel_id)
        msg = await fetch_client.get_messages(channel_id, message_id)
        if msg:
            log.info(f"Tier 2 succeeded for channel {channel_id}")
            return msg
    except Exception as e:
        log.warning(f"Tier 2 failed for channel {channel_id}: {e}")

    # --- Tier 3: Raw MTProto API with stored access_hash ---
    access_hash = doc.get("channel_access_hash")
    if access_hash is None:
        raise HTTPException(
            503,
            f"Cannot resolve channel {channel_id}: peer not cached and no "
            f"access_hash in DB. Re-sync this video with updated sync.py."
        )

    log.info(f"Using raw MTProto API for message {message_id} (tier 3)...")
    try:
        raw_channel_id = abs(channel_id) - 1000000000000
        input_channel = raw_types.InputChannel(
            id=raw_channel_id,
            access_hash=access_hash
        )
        r = await fetch_client.invoke(
            raw_functions.channels.GetMessages(
                channel=input_channel,
                id=[raw_types.InputMessageID(id=message_id)]
            )
        )
        from pyrogram import utils as pyro_utils
        messages_list = await pyro_utils.parse_messages(fetch_client, r)
        if messages_list:
            log.info(f"Tier 3 succeeded for channel {channel_id}")
            return messages_list[0]
        raise HTTPException(503, "Message not found via raw API")
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Tier 3 failed: {e}")
        raise HTTPException(503, f"All peer resolution methods failed: {e}")


async def _extract_file_info(msg) -> dict:
    """Extract file_id, file_size, mime_type, and filename from a message."""
    file_id = None
    file_size = 0
    mime_type = "video/mp4"
    file_name = None

    if msg.video:
        file_id = msg.video.file_id
        file_size = msg.video.file_size or 0
        mime_type = msg.video.mime_type or "video/mp4"
        file_name = msg.video.file_name
    elif msg.document:
        file_id = msg.document.file_id
        file_size = msg.document.file_size or 0
        mime_type = msg.document.mime_type or "application/octet-stream"
        file_name = msg.document.file_name
    elif msg.audio:
        file_id = msg.audio.file_id
        file_size = msg.audio.file_size or 0
        mime_type = msg.audio.mime_type or "audio/mpeg"
        file_name = msg.audio.file_name
    else:
        raise HTTPException(400, "Message has no downloadable media")

    if not file_id:
        raise HTTPException(400, "No file_id from fresh message")

    if file_size <= 0:
        raise HTTPException(400, "Invalid file size")

    return {
        "file_id": file_id,
        "file_size": file_size,
        "mime_type": mime_type,
        "file_name": file_name,
    }


async def _update_db_with_fresh_info(doc: dict, msg, file_info: dict):
    """Update the DB with fresh file_id and metadata from the fetched message."""
    try:
        update_set = {
            "file_id": file_info["file_id"],
            "bot_file_id": file_info["file_id"],
            "file_size": file_info["file_size"],
            "mime_type": file_info["mime_type"],
            "synced_at": datetime.now(timezone.utc),
        }
        if file_info["file_name"]:
            update_set["file_name"] = file_info["file_name"]

        # Update thumbnail file_id
        media = msg.video or msg.document
        if media and hasattr(media, "thumbs") and media.thumbs:
            try:
                new_thumb_id = max(media.thumbs, key=lambda t: t.width or 0).file_id
                if new_thumb_id:
                    update_set["thumb_file_id"] = new_thumb_id
            except (ValueError, AttributeError):
                pass

        await videos_col.update_one(
            {"_id": doc["_id"]},
            {"$set": update_set}
        )
    except Exception as e:
        log.warning(f"Could not update DB with fresh file_id: {e}")


async def build_stream_response(
    doc: dict,
    request: Request,
    force_download: bool = False,
    custom_filename: str = None
):
    """Build a streaming or download response — Vinnoflow/FileToLink approach.

    On EVERY request, we fetch the message fresh from Telegram to get a
    valid file_id with a fresh file reference. This means:
      - No stored file_id dependency (never expires)
      - No refresh logic needed
      - Permanent links (work as long as the message exists in the channel)
      - No "Content-Length mismatch" crashes

    Args:
        doc: The video document from MongoDB
        request: The FastAPI request object
        force_download: If True, sets Content-Disposition: attachment
        custom_filename: Override filename for download
    """
    # Step 1: Fetch the message fresh from Telegram
    msg = await _fetch_message_fresh(doc)

    # Step 2: Extract file info from the fresh message
    file_info = await _extract_file_info(msg)

    # Step 3: Update DB with fresh file_id (for thumbnails, etc.)
    await _update_db_with_fresh_info(doc, msg, file_info)

    # Step 4: Parse range header for seeking support
    client = _get_stream_client()
    range_header = request.headers.get("range")
    start, end = _parse_range(range_header, file_info["file_size"])
    length = end - start + 1

    chunk_offset = start // CHUNK_SIZE
    discard = start % CHUNK_SIZE
    chunk_limit = math.ceil((length + discard) / CHUNK_SIZE)

    # Step 5: Determine filename and Content-Disposition
    filename = custom_filename or file_info["file_name"]
    if not filename:
        # Generate filename from title
        title = doc.get("title", "download")
        ext = get_file_extension(file_info["mime_type"])
        filename = f"{sanitize_filename(title)}.{ext}"
    else:
        filename = sanitize_filename(filename)

    # Step 6: Stream the file using the FRESH file_id
    file_id = file_info["file_id"]

    async def stream_generator():
        sent = 0
        try:
            async with _stream_semaphore:
                try:
                    async for chunk in client.stream_media(
                        file_id, limit=chunk_limit, offset=chunk_offset
                    ):
                        if await request.is_disconnected():
                            return
                        if not chunk:
                            continue
                        # Discard partial first chunk for byte-range seeking
                        if sent == 0 and discard > 0:
                            chunk = chunk[discard:]
                        if not chunk:
                            continue
                        remaining = length - sent
                        if len(chunk) >= remaining:
                            yield chunk[:remaining]
                            return
                        yield chunk
                        sent += len(chunk)
                except FileReferenceExpired:
                    log.warning("FileReferenceExpired during stream (unexpected)")
                    return
                except FloodWait as e:
                    log.warning(f"FloodWait {e.value}s during stream")
                    await asyncio.sleep(e.value + 1)
                    return
                except Exception as e:
                    log.warning(f"Stream error: {e}")
                    return
        except ClientDisconnect:
            return
        except Exception as e:
            log.warning(f"Stream generator error: {e}")
            return

    # Step 7: Build headers
    headers = {
        "Accept-Ranges": "bytes",
        "Content-Length": str(length),
        "Cache-Control": "public, max-age=86400",
    }

    # Content-Disposition: attachment for downloads, inline for streaming
    if force_download:
        # RFC 5987 encoding for non-ASCII filenames
        quoted_filename = quote(filename)
        headers["Content-Disposition"] = f"attachment; filename=\"{quoted_filename}\"; filename*=UTF-8''{quoted_filename}"
    else:
        quoted_filename = quote(filename)
        headers["Content-Disposition"] = f"inline; filename=\"{quoted_filename}\""

    status_code = 200
    if range_header:
        headers["Content-Range"] = f"bytes {start}-{end}/{file_info['file_size']}"
        status_code = 206

    return StreamingResponse(
        stream_generator(),
        status_code=status_code,
        media_type=file_info["mime_type"],
        headers=headers,
    )


# -------------------------------------------------------------------
# STREAMING ENDPOINTS (Vinnoflow-style permanent links)
# -------------------------------------------------------------------

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
    """Authenticated streaming endpoint — requires login token."""
    doc = await videos_col.find_one({"_id": validate_object_id(vid)})
    if not doc:
        raise HTTPException(404, "Not found")
    return await build_stream_response(doc, request, force_download=False)


# -------------------------------------------------------------------
# PERMANENT STREAMING LINK (Vinnoflow-style — no auth, no expiry)
# -------------------------------------------------------------------
@web.get("/watch/{message_id}/{file_unique_id}")
@web.get("/watch/{message_id}/{file_unique_id}.mp4")
async def watch_permanent(
    message_id: int,
    file_unique_id: str,
    request: Request,
):
    """Permanent streaming link — Vinnoflow/FileToLink style.

    The URL is permanent: no hash, no expiry, no auth required.
    Anyone with the link can stream.
    The link stays active as long as the message exists in the channel.
    If the channel owner deletes the message, the link stops working (404).

    The file_unique_id in the URL acts as a hard-to-guess token — it's a
    random-looking string that makes the URL unguessable even if someone
    knows the message_id pattern.
    """
    doc = await videos_col.find_one(
        {"message_id": message_id, "file_unique_id": file_unique_id}
    )
    if not doc:
        raise HTTPException(404, "Not found")

    return await build_stream_response(doc, request, force_download=False)


# -------------------------------------------------------------------
# PERMANENT DOWNLOAD LINK (Vinnoflow-style — no auth, no expiry)
# -------------------------------------------------------------------
@web.get("/download/{message_id}/{file_unique_id}")
@web.get("/download/{message_id}/{file_unique_id}/{filename}")
async def download_permanent(
    message_id: int,
    file_unique_id: str,
    request: Request,
    filename: str = None,
):
    """Permanent download link — Vinnoflow/FileToLink style.

    Same as /watch/ but forces download (Content-Disposition: attachment)
    instead of inline streaming. The browser will prompt the user to save
    the file instead of playing it.

    The URL is permanent: no hash, no expiry, no auth required.
    """
    doc = await videos_col.find_one(
        {"message_id": message_id, "file_unique_id": file_unique_id}
    )
    if not doc:
        raise HTTPException(404, "Not found")

    return await build_stream_response(
        doc, request, force_download=True, custom_filename=filename
    )


# -------------------------------------------------------------------
# URL GENERATION ENDPOINTS
# -------------------------------------------------------------------
@web.get("/api/video/{vid}/watch-url")
async def get_watch_url(vid: str, user=Depends(auth)):
    """Return a PERMANENT streaming URL for the video.

    Vinnoflow style: the URL has no expiry, no hash. It works forever
    (as long as the message exists in the channel).
    """
    doc = await videos_col.find_one(
        {"_id": validate_object_id(vid)},
        {"message_id": 1, "file_unique_id": 1, "title": 1, "mime_type": 1},
    )
    if not doc:
        raise HTTPException(404, "Not found")
    if not BASE_URL:
        raise HTTPException(500, "PUBLIC_BASE_URL is not configured on the server")
    if not doc.get("message_id") or not doc.get("file_unique_id"):
        raise HTTPException(500, "Video is missing message_id or file_unique_id")

    url = f"{BASE_URL}/watch/{doc['message_id']}/{doc['file_unique_id']}"
    return {
        "url": url,
        "type": "stream",
        "permanent": True,
        "expires": None,
    }


@web.get("/api/video/{vid}/download-url")
async def get_download_url(vid: str, user=Depends(auth)):
    """Return a PERMANENT download URL for the video.

    Vinnoflow style: the URL has no expiry, no hash. It works forever
    (as long as the message exists in the channel).
    """
    doc = await videos_col.find_one(
        {"_id": validate_object_id(vid)},
        {"message_id": 1, "file_unique_id": 1, "title": 1, "mime_type": 1},
    )
    if not doc:
        raise HTTPException(404, "Not found")
    if not BASE_URL:
        raise HTTPException(500, "PUBLIC_BASE_URL is not configured on the server")
    if not doc.get("message_id") or not doc.get("file_unique_id"):
        raise HTTPException(500, "Video is missing message_id or file_unique_id")

    url = f"{BASE_URL}/download/{doc['message_id']}/{doc['file_unique_id']}"
    return {
        "url": url,
        "type": "download",
        "permanent": True,
        "expires": None,
    }


@web.get("/api/video/{vid}/links")
async def get_all_links(vid: str, user=Depends(auth)):
    """Return both streaming and download URLs for a video."""
    doc = await videos_col.find_one(
        {"_id": validate_object_id(vid)},
        {"message_id": 1, "file_unique_id": 1, "title": 1, "mime_type": 1, "file_size": 1},
    )
    if not doc:
        raise HTTPException(404, "Not found")
    if not BASE_URL:
        raise HTTPException(500, "PUBLIC_BASE_URL is not configured on the server")
    if not doc.get("message_id") or not doc.get("file_unique_id"):
        raise HTTPException(500, "Video is missing message_id or file_unique_id")

    mid = doc["message_id"]
    fuid = doc["file_unique_id"]
    return {
        "stream_url": f"{BASE_URL}/watch/{mid}/{fuid}",
        "download_url": f"{BASE_URL}/download/{mid}/{fuid}",
        "permanent": True,
        "expires": None,
        "title": doc.get("title", ""),
        "file_size": doc.get("file_size", 0),
    }


# -------------------------------------------------------------------
# THUMBNAILS
# -------------------------------------------------------------------
@web.get("/api/thumb/{vid}")
async def get_thumb(vid: str):
    """Stream a video thumbnail — Vinnoflow approach.

    Fetch the message fresh from Telegram to get a valid thumbnail file_id,
    then stream the thumbnail. Cached in memory for performance.
    """
    try:
        oid = ObjectId(vid)
    except (InvalidId, TypeError):
        raise HTTPException(404, "Not found")

    cached = thumb_cache.get(vid)
    if cached:
        return Response(content=cached, media_type="image/jpeg")

    if bot_app is None or not _clients_started["bot"]:
        raise HTTPException(503, "Thumbnail service not available")

    doc = await videos_col.find_one(
        {"_id": oid},
        {"thumb_file_id": 1, "channel_id": 1, "message_id": 1,
         "channel_access_hash": 1}
    )
    if not doc:
        raise HTTPException(404, "Not found")

    try:
        msg = await _fetch_message_fresh(doc)
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Thumbnail fetch failed: {e}")
        raise HTTPException(503, "Thumbnail unavailable")

    thumb_file_id = None
    media = msg.video or msg.document
    if media and hasattr(media, "thumbs") and media.thumbs:
        try:
            thumb_file_id = max(media.thumbs, key=lambda t: t.width or 0).file_id
        except (ValueError, AttributeError):
            pass

    if not thumb_file_id:
        raise HTTPException(404, "No thumbnail available")

    try:
        await videos_col.update_one(
            {"_id": oid},
            {"$set": {"thumb_file_id": thumb_file_id}}
        )
    except Exception:
        pass

    async def stream_thumb():
        buffer = io.BytesIO()
        try:
            async for chunk in bot_app.stream_media(thumb_file_id):
                if chunk:
                    buffer.write(chunk)
                    yield chunk
            await thumb_cache.set(vid, buffer.getvalue())
        except Exception as e:
            log.error(f"Thumbnail stream error: {e}")

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
    order = {str(i): idx for idx, i in enumerate(reversed(raw_hist))}
    docs.sort(key=lambda x: order.get(str(x["_id"]), 9999))
    return [format_video_doc(d) for d in docs]


@web.post("/api/user/history/{vid}")
async def add_history(vid: str, user: dict = Depends(auth)):
    validate_object_id(vid)
    await users_col.update_one({"_id": user["_id"]}, {"$pull": {"history": vid}})
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
            "base_url": BASE_URL or "not configured",
        }
    except Exception as e:
        return JSONResponse({"status": "degraded", "error": str(e)}, status_code=503)


@web.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:web", host="0.0.0.0", port=8000, reload=True)
