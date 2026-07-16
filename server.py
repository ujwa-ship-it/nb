import os
import re
import math
import secrets
import asyncio
import logging
import io
from collections import OrderedDict
from urllib.parse import quote
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from typing import Optional, Any

from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import DuplicateKeyError
from pyrogram import Client, filters
from pyrogram.types import Message
from pyrogram.errors import FloodWait
try:
    from pyrogram.errors import FileReferenceExpired, PeerIdInvalid
except ImportError:
    logging.error(
        "pyrogram.errors.FileReferenceExpired/PeerIdInvalid not found — "
        "file-reference recovery is DISABLED. Check your pyrogram version."
    )
    class FileReferenceExpired(Exception):
        pass
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

from bson import ObjectId
from bson.errors import InvalidId
import bcrypt
from dotenv import load_dotenv

load_dotenv()

# ===================================================================
# Logging
# ===================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
log = logging.getLogger("nexstream")
logging.getLogger("pyrogram").setLevel(logging.WARNING)

class _SuppressFileRefExpired(logging.Filter):
    def filter(self, record):
        return "FILE_REFERENCE_EXPIRED" not in record.getMessage()

logging.getLogger("pyrogram.client").addFilter(_SuppressFileRefExpired())

class StreamAbort(Exception):
    pass

# ===================================================================
# Config
# ===================================================================
def _get_env_or_raise(key: str) -> str:
    v = os.getenv(key)
    if v is None or v == "":
        raise SystemExit(f"❌ Missing required environment variable: {key}")
    return v

MONGO_URL           = _get_env_or_raise("MONGO_URL")
BOT_TOKEN           = _get_env_or_raise("BOT_TOKEN")
TELEGRAM_API_ID     = int(_get_env_or_raise("TELEGRAM_API_ID"))
TELEGRAM_API_HASH   = _get_env_or_raise("TELEGRAM_API_HASH")
BASE_URL            = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
SESSION_STRING      = os.getenv("SESSION_STRING", "").strip()

CHANNELS_RAW = os.getenv("SYNC_CHANNELS", "")
CHANNELS = [int(ch.strip()) for ch in CHANNELS_RAW.split(",") if ch.strip()]

# ── Render Free-Tier Memory Limits ──────────────────────────────────
CHUNK_SIZE             = 1024 * 1024                        # 1 MB
MAX_CONCURRENT_STREAMS = int(os.getenv("MAX_CONCURRENT_STREAMS", "4"))
MAX_CONCURRENT_THUMBS  = int(os.getenv("MAX_CONCURRENT_THUMBS", "6"))
MAX_THUMB_CACHE        = int(os.getenv("MAX_THUMB_CACHE", "100"))
MAX_DOC_CACHE          = int(os.getenv("MAX_DOC_CACHE", "100"))

# Item 1: Prefetch 6 chunks (6MB) ahead to prevent lockstep streaming
READAHEAD_CHUNKS       = int(os.getenv("READAHEAD_CHUNKS", "6"))

FLOOD_MAX_RETRIES      = int(os.getenv("FLOOD_MAX_RETRIES", "5"))
FLOOD_MAX_TOTAL_WAIT   = int(os.getenv("FLOOD_MAX_TOTAL_WAIT", "180"))
STREAM_WALL_CLOCK_BUDGET = int(os.getenv("STREAM_WALL_CLOCK_BUDGET", "300"))

EXTRA_CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024 * 1024

# ===================================================================
# Database
# ===================================================================
mongo = AsyncIOMotorClient(MONGO_URL, tz_aware=True, serverSelectionTimeoutMS=10000)
db = mongo.nexstream
videos_col     = db.videos
users_col      = db.users
channel_hashes = db.channel_hashes

# ===================================================================
# MTProto Clients
# ===================================================================
stream_client: Optional[Client] = None
bot_app: Optional[Client] = None
_clients_started: dict = {"stream": False, "bot": False}
_stream_semaphore = asyncio.Semaphore(MAX_CONCURRENT_STREAMS)
_thumb_semaphore = asyncio.Semaphore(MAX_CONCURRENT_THUMBS)

# ===================================================================
# Caches
# ===================================================================
class LRUCache:
    def __init__(self, max_size: int = MAX_DOC_CACHE):
        self._max = max_size
        self._data: OrderedDict = OrderedDict()
        self._lock = asyncio.Lock()

    def get(self, key: str) -> Optional[Any]:
        if key in self._data:
            self._data.move_to_end(key)
            return self._data[key]
        return None

    async def set(self, key: str, value: Any):
        async with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = value
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    async def invalidate(self, key: str):
        async with self._lock:
            self._data.pop(key, None)

    async def clear(self):
        async with self._lock:
            self._data.clear()

thumb_cache = LRUCache(MAX_THUMB_CACHE)
doc_cache   = LRUCache(MAX_DOC_CACHE)

# ===================================================================
# Helpers
# ===================================================================
async def _call_with_flood_retry(fn, *args, max_retries=3, max_total_wait=60, **kwargs):
    total_wait = 0.0
    for attempt in range(max_retries + 1):
        try:
            return await fn(*args, **kwargs)
        except FloodWait as e:
            if attempt == max_retries or total_wait + e.value > max_total_wait:
                raise
            wait = e.value + 1
            log.warning(f"FloodWait {e.value}s on {getattr(fn, '__name__', str(fn))} (retry {attempt + 1}/{max_retries})")
            await asyncio.sleep(wait)
            total_wait += wait

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
    return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email))

def escape_regex(text: str) -> str:
    return re.escape(text)

def sanitize_filename(filename: str) -> str:
    if not filename:
        return "download"
    filename = re.sub(r'[\\/:*?"<>|\r\n]', '_', filename)
    if len(filename) > 200:
        name, _, ext = filename.rpartition('.')
        filename = (name[:190] + '.' + ext) if ext else filename[:200]
    return filename

def get_file_extension(mime_type: str, filename: str = "") -> str:
    if filename and '.' in filename:
        ext = filename.rsplit('.', 1)[-1]
        if ext and len(ext) <= 5:
            return ext.lower()
    mime_to_ext = {
        "video/mp4": "mp4", "video/x-matroska": "mkv", "video/webm": "webm",
        "video/avi": "avi", "video/quicktime": "mov", "video/x-flv": "flv",
        "video/mpeg": "mpeg", "video/3gpp": "3gp",
        "audio/mpeg": "mp3", "audio/ogg": "ogg", "audio/wav": "wav",
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

# ===================================================================
# Cached Video Lookups
# ===================================================================
async def _get_video_by_id(oid: ObjectId) -> Optional[dict]:
    key = f"id:{oid}"
    cached = doc_cache.get(key)
    if cached is not None:
        return dict(cached)
    doc = await videos_col.find_one({"_id": oid})
    if doc:
        await doc_cache.set(key, doc)
        return dict(doc)
    return None

async def _get_video_by_message(message_id: int, file_unique_id: str) -> Optional[dict]:
    key = f"msg:{message_id}:{file_unique_id}"
    cached = doc_cache.get(key)
    if cached is not None:
        return dict(cached)
    doc = await videos_col.find_one({"message_id": message_id, "file_unique_id": file_unique_id})
    if doc:
        await doc_cache.set(key, doc)
        await doc_cache.set(f"id:{doc['_id']}", doc)
        return dict(doc)
    return None

async def _invalidate_video_cache(doc_id: ObjectId, message_id: int = None, file_unique_id: str = None):
    await doc_cache.invalidate(f"id:{doc_id}")
    if message_id and file_unique_id:
        await doc_cache.invalidate(f"msg:{message_id}:{file_unique_id}")

# ===================================================================
# Access-Hash Helpers
# ===================================================================
async def _save_access_hash(channel_id: int, access_hash: int):
    try:
        await channel_hashes.update_one(
            {"channel_id": channel_id},
            {"$set": {"channel_id": channel_id, "access_hash": access_hash, "updated_at": datetime.now(timezone.utc)}},
            upsert=True,
        )
        await videos_col.update_many({"channel_id": channel_id}, {"$set": {"channel_access_hash": access_hash}})
    except Exception as e:
        log.warning(f"Could not save access_hash for {channel_id}: {e}")

async def _get_access_hash_from_db(channel_id: int) -> Optional[int]:
    try:
        ch_doc = await channel_hashes.find_one({"channel_id": channel_id})
        if ch_doc and ch_doc.get("access_hash") is not None:
            return ch_doc["access_hash"]
    except Exception:
        pass
    try:
        v_doc = await videos_col.find_one(
            {"channel_id": channel_id, "channel_access_hash": {"$exists": True, "$ne": None}},
            {"channel_access_hash": 1},
        )
        if v_doc and v_doc.get("channel_access_hash") is not None:
            return v_doc["channel_access_hash"]
    except Exception:
        pass
    return None

# ===================================================================
# SYNC LOGIC
# ===================================================================
def _detect_type(caption: str) -> str:
    if not caption: return "movie"
    m = re.search(r"#(movie|game)s?\b", caption, re.IGNORECASE)
    return m.group(1).lower() if m else "movie"

def _parse_genres(caption: str) -> list:
    if not caption: return []
    matches = re.findall(r"#genre-([\w-]+)", caption, re.IGNORECASE)
    seen, out = set(), []
    for g in matches:
        gl = g.lower()
        if gl not in seen:
            seen.add(gl)
            out.append(gl)
    return out

def _build_doc(message: Message) -> dict:
    media = message.video or message.document
    vid = media
    title = (message.caption or vid.file_name or "Untitled")[:500]
    thumb_file_id = None
    thumbs = getattr(vid, "thumbs", None)
    if thumbs:
        try: thumb_file_id = max(thumbs, key=lambda t: (t.width or 0)).file_id
        except (ValueError, AttributeError): thumb_file_id = None
    caption = message.caption or message.text or ""
    return {
        "file_unique_id": vid.file_unique_id, "file_id": vid.file_id, "bot_file_id": vid.file_id,
        "file_name": vid.file_name or "", "title": title, "desc": caption[:2000],
        "duration": getattr(vid, "duration", 0) or 0, "width": getattr(vid, "width", 0) or 0,
        "height": getattr(vid, "height", 0) or 0, "file_size": vid.file_size or 0,
        "mime_type": vid.mime_type or "video/mp4", "thumb_file_id": thumb_file_id,
        "channel_id": message.chat.id, "message_id": message.id, "views": message.views or 0,
        "date": message.date, "type": _detect_type(caption), "genres": _parse_genres(caption),
        "year": message.date.year if message.date else datetime.now(timezone.utc).year,
        "synced_at": datetime.now(timezone.utc),
    }

async def _prewarm_thumbnail(doc_id, thumb_file_id: str):
    if not thumb_file_id: return
    try:
        client = _get_thumb_client()
        data = await asyncio.wait_for(_call_with_flood_retry(client.download_media, thumb_file_id, in_memory=True), timeout=10)
        content = data.read() if hasattr(data, "read") else bytes(data)
        if content:
            await thumb_cache.set(str(doc_id), content)
    except Exception as e:
        log.warning(f"Thumbnail pre-warm failed for {doc_id}: {e}")

async def _upsert_video(client: Client, message: Message):
    media = message.video or message.document
    if not media: return
    mime = (media.mime_type or "").lower()
    if not (bool(message.video) or mime.startswith("video")): return

    if media.file_size and media.file_size > MAX_FILE_SIZE_BYTES:
        try:
            await videos_col.delete_one({"file_unique_id": media.file_unique_id})
        except Exception: pass
        return

    doc = _build_doc(message)

    try:
        peer = await _call_with_flood_retry(client.resolve_peer, message.chat.id)
        if hasattr(peer, "access_hash") and peer.access_hash:
            doc["channel_access_hash"] = peer.access_hash
            await _save_access_hash(message.chat.id, peer.access_hash)
    except Exception as e:
        log.warning(f"Could not resolve peer for access_hash: {e}")

    update = {"$set": doc, "$setOnInsert": {"rating": 0}}
    try:
        # Item 4: Match on channel_id+message_id OR file_unique_id to handle edited media safely
        result = await videos_col.update_one(
            {
                "$or": [
                    {"channel_id": doc["channel_id"], "message_id": doc["message_id"]},
                    {"file_unique_id": doc["file_unique_id"]}
                ]
            },
            update,
            upsert=True,
        )
        if result.upserted_id:
            await doc_cache.invalidate(f"id:{result.upserted_id}")
            if doc.get("thumb_file_id"):
                asyncio.create_task(_prewarm_thumbnail(result.upserted_id, doc["thumb_file_id"]))
    except Exception as e:
        log.error(f"❌ Failed to sync '{doc['title']}': {e}")

def _register_sync_handlers(client: Client):
    if not CHANNELS: return
    video_filter = filters.chat(CHANNELS) & (filters.video | filters.document)

    @client.on_message(video_filter)
    async def new_media_handler(c, message): await _upsert_video(c, message)

    @client.on_edited_message(video_filter)
    async def edited_media_handler(c, message): await _upsert_video(c, message)

    @client.on_deleted_messages(filters.chat(CHANNELS))
    async def deleted_media_handler(c, messages: list):
        for message in messages:
            try:
                chat_id = message.chat.id if message.chat else None
                q = {"message_id": message.id, "channel_id": {"$in": CHANNELS}} if chat_id is None else {"channel_id": chat_id, "message_id": message.id}
                await videos_col.delete_many(q)
            except Exception as e:
                log.error(f"❌ Failed to handle deleted message {message.id}: {e}")

# ===================================================================
# Background Cleanup
# ===================================================================
async def _cleanup_deleted_videos():
    await asyncio.sleep(60)
    while True:
        try:
            channels_data = await videos_col.aggregate([{"$group": {"_id": "$channel_id", "msg_ids": {"$push": "$message_id"}}}]).to_list(length=None)
            client = stream_client if _clients_started.get("stream") else bot_app
            if not client:
                await asyncio.sleep(21600); continue
            for ch_data in channels_data:
                ch_id, msg_ids = ch_data["_id"], ch_data["msg_ids"]
                if not ch_id or not msg_ids: continue
                for i in range(0, len(msg_ids), 100):
                    batch = msg_ids[i:i+100]
                    try:
                        msgs = await _call_with_flood_retry(client.get_messages, ch_id, batch)
                        existing_ids = {m.id for m in msgs if m and not getattr(m, "empty", False)}
                        deleted_ids = set(batch) - existing_ids
                        if deleted_ids:
                            await videos_col.delete_many({"channel_id": ch_id, "message_id": {"$in": list(deleted_ids)}})
                    except Exception: continue
        except Exception: pass
        await asyncio.sleep(21600)

async def _force_resolve_channels():
    if not CHANNELS: return
    await asyncio.sleep(3)
    for channel_id in CHANNELS:
        resolved = False
        for attempt in range(5):
            for client_name, client in [("bot", bot_app), ("stream", stream_client)]:
                if client is None or not _clients_started.get(client_name): continue
                try:
                    peer = await _call_with_flood_retry(client.resolve_peer, channel_id)
                    if hasattr(peer, "access_hash") and peer.access_hash:
                        await _save_access_hash(channel_id, peer.access_hash)
                        resolved = True; break
                except Exception: pass
            if resolved: break
            for client_name, client in [("bot", bot_app), ("stream", stream_client)]:
                if client is None or not _clients_started.get(client_name): continue
                try:
                    await client.get_chat(channel_id)
                    peer = await _call_with_flood_retry(client.resolve_peer, channel_id)
                    if hasattr(peer, "access_hash") and peer.access_hash:
                        await _save_access_hash(channel_id, peer.access_hash)
                        resolved = True; break
                except Exception: pass
            if resolved: break
            await asyncio.sleep(3)

async def _backfill_access_hashes():
    try:
        channels = await videos_col.aggregate([
            {"$match": {"channel_access_hash": {"$exists": False}}},
            {"$group": {"_id": "$channel_id"}}
        ]).to_list(length=1000)
        for ch_doc in channels:
            channel_id = ch_doc["_id"]
            if not channel_id: continue
            access_hash = await _get_access_hash_from_db(channel_id)
            if access_hash is None:
                for client_name, client in [("bot", bot_app), ("stream", stream_client)]:
                    if client is None or not _clients_started.get(client_name): continue
                    try:
                        peer = await _call_with_flood_retry(client.resolve_peer, channel_id)
                        if hasattr(peer, "access_hash") and peer.access_hash:
                            access_hash = peer.access_hash; break
                    except Exception: continue
            if access_hash is not None:
                await _save_access_hash(channel_id, access_hash)
    except Exception as e:
        log.error(f"Backfill task error: {e}")

# ===================================================================
# Lifespan & Exception Handler
# ===================================================================
def _suppress_pyrogram_peer_errors(loop, context):
    exc = context.get("exception")
    if isinstance(exc, ValueError) and "Peer id invalid" in str(exc): return
    loop.default_exception_handler(context)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global stream_client, bot_app
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(_suppress_pyrogram_peer_errors)

    if not BASE_URL:
        log.warning("PUBLIC_BASE_URL not set — thumb_url/stream_url will be relative.")

    bot_app = Client("nexstream_bot", api_id=TELEGRAM_API_ID, api_hash=TELEGRAM_API_HASH, bot_token=BOT_TOKEN, in_memory=True)
    try:
        await bot_app.start(); _clients_started["bot"] = True
    except FloodWait as e:
        await asyncio.sleep(e.value + 1); await bot_app.start(); _clients_started["bot"] = True

    _register_sync_handlers(bot_app)

    if SESSION_STRING:
        stream_client = Client("nexstream_user", api_id=TELEGRAM_API_ID, api_hash=TELEGRAM_API_HASH, session_string=SESSION_STRING, in_memory=True)
        try:
            await stream_client.start(); _clients_started["stream"] = True
        except Exception:
            stream_client = None

    await ensure_indexes()
    asyncio.create_task(_force_resolve_channels())
    asyncio.create_task(_backfill_access_hashes())
    asyncio.create_task(_cleanup_deleted_videos())
    yield

    for c in (stream_client, bot_app):
        if c is not None:
            try: await c.stop()
            except Exception: pass

class MediaAwareGZipMiddleware:
    STREAM_PREFIXES = ("/watch/", "/download/", "/api/stream/", "/api/thumb/")
    def __init__(self, app: ASGIApp, minimum_size: int = 1000) -> None:
        self.app = app
        self.gzip_app = GZipMiddleware(app, minimum_size=minimum_size)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            if any(scope.get("path", "").startswith(p) for p in self.STREAM_PREFIXES):
                await self.app(scope, receive, send); return
        await self.gzip_app(scope, receive, send)

web = FastAPI(lifespan=lifespan, docs_url="/docs", redoc_url=None)
web.add_middleware(MediaAwareGZipMiddleware, minimum_size=1000)
web.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5500", "http://127.0.0.1:5500", "https://nb-orwg.onrender.com", "https://obst.netlify.app", "https://obstr.netlify.app"] + EXTRA_CORS_ORIGINS,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

@web.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException): raise exc
    if isinstance(exc, StreamAbort): return Response(status_code=204, content=b"")
    log.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": f"Internal server error: {type(exc).__name__}"})

async def ensure_indexes():
    try:
        existing = await videos_col.index_information()
        if "channel_id_1_message_id_1" in existing and not existing["channel_id_1_message_id_1"].get("unique", False):
            await videos_col.drop_index("channel_id_1_message_id_1")
        await videos_col.create_index("file_unique_id", unique=True, sparse=True)
        await videos_col.create_index([("channel_id", 1), ("message_id", 1)], unique=True, name="channel_message_unique")
        await videos_col.create_index("type")
        await videos_col.create_index([("title", "text")])
        await videos_col.create_index("date")
        await users_col.create_index("token")
        await users_col.create_index("email", unique=True, sparse=True)
        await channel_hashes.create_index("channel_id", unique=True)
    except Exception as e:
        log.warning("Could not ensure indexes: %s", e)

def format_video_doc(d: dict) -> Optional[dict]:
    if d is None: return None
    d = dict(d)
    d["id"] = str(d.pop("_id"))
    base = BASE_URL or ""
    d["thumb_url"] = f"{base}/api/thumb/{d['id']}" if d.get("thumb_file_id") else ""
    if d.get("message_id") and d.get("file_unique_id"):
        d["stream_url"]   = f"{base}/watch/{d['message_id']}/{d['file_unique_id']}"
        d["download_url"] = f"{base}/download/{d['message_id']}/{d['file_unique_id']}"
    else:
        d["stream_url"] = ""; d["download_url"] = ""
    d["vlc_url"] = f"{base}/api/video/{d['id']}/vlc"
    if not d.get("genres"): d["genres"] = []
    if d.get("type") not in ("movie", "game"): d["type"] = "movie"
    return d

def _get_stream_client() -> Client:
    if stream_client is not None and _clients_started["stream"]: return stream_client
    if bot_app is not None and _clients_started["bot"]: return bot_app
    raise HTTPException(503, "Streaming service not available")

def _get_thumb_client() -> Client:
    if stream_client is not None and _clients_started["stream"]: return stream_client
    if bot_app is not None and _clients_started["bot"]: return bot_app
    raise HTTPException(503, "Thumbnail service not available")

# ===================================================================
# AUTH ROUTES
# ===================================================================
@web.post("/api/auth/register")
async def register(data: dict):
    name, email, pw = str(data.get("name", "")).strip(), str(data.get("email", "")).strip().lower(), str(data.get("password", ""))
    if not name or not is_valid_email(email) or len(pw) < 6: raise HTTPException(400, "Invalid input")
    token, loop = secrets.token_hex(32), asyncio.get_running_loop()
    hashed = await loop.run_in_executor(None, hash_pw, pw)
    expires = datetime.now(timezone.utc) + timedelta(days=30)
    try:
        await users_col.insert_one({"name": name, "email": email, "password": hashed, "token": token, "expires_at": expires, "my_list": [], "history": [], "created_at": datetime.now(timezone.utc)})
    except DuplicateKeyError: raise HTTPException(400, "Email already exists")
    return {"token": token, "name": name, "email": email}

@web.post("/api/auth/login")
async def login(data: dict):
    email, pw = str(data.get("email", "")).strip().lower(), str(data.get("password", ""))
    user = await users_col.find_one({"email": email})
    if not user: raise HTTPException(401, "Wrong email or password")
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, verify_pw, pw, user["password"]): raise HTTPException(401, "Wrong email or password")
    token = secrets.token_hex(32)
    await users_col.update_one({"_id": user["_id"]}, {"$set": {"token": token, "expires_at": datetime.now(timezone.utc) + timedelta(days=30)}})
    return {"token": token, "name": user["name"], "email": user["email"]}

@web.get("/api/auth/me")
async def me(user: dict = Depends(auth)): return {"name": user["name"], "email": user["email"]}

@web.post("/api/auth/logout")
async def logout(user: dict = Depends(auth)):
    await users_col.update_one({"_id": user["_id"]}, {"$unset": {"token": "", "expires_at": ""}})
    return {"ok": True}

# ===================================================================
# MOVIES / GAMES / SEARCH
# ===================================================================
def _apply_genre_filter(q: dict, genre: str):
    if genre and genre.lower() != "all": q["genres"] = {"$in": [genre.lower()]}

@web.get("/api/movies")
async def get_movies(page: int = 1, limit: int = 20, genre: str = ""):
    page, limit = max(1, page), max(1, min(limit, 100))
    q = {"type": "movie"}; _apply_genre_filter(q, genre)
    docs = await videos_col.find(q).sort("date", -1).skip((page - 1) * limit).limit(limit).to_list(length=limit)
    return {"total": await videos_col.count_documents(q), "page": page, "data": [format_video_doc(d) for d in docs]}

@web.get("/api/games")
async def get_games(page: int = 1, limit: int = 20, genre: str = ""):
    page, limit = max(1, page), max(1, min(limit, 100))
    q = {"type": "game"}; _apply_genre_filter(q, genre)
    docs = await videos_col.find(q).sort("date", -1).skip((page - 1) * limit).limit(limit).to_list(length=limit)
    return {"total": await videos_col.count_documents(q), "page": page, "data": [format_video_doc(d) for d in docs]}

@web.get("/api/movies/{vid}")
async def get_movie(vid: str):
    doc = await _get_video_by_id(validate_object_id(vid))
    if not doc: raise HTTPException(404, "Not found")
    return format_video_doc(doc)

@web.get("/api/search")
async def search(q: str = "", page: int = 1, limit: int = 20):
    if not q or len(q) < 2: return {"total": 0, "page": page, "data": []}
    page, limit = max(1, page), max(1, min(limit, 100))
    q_filter = {"title": {"$regex": escape_regex(q), "$options": "i"}}
    docs = await videos_col.find(q_filter).sort("date", -1).skip((page - 1) * limit).limit(limit).to_list(length=limit)
    return {"total": await videos_col.count_documents(q_filter), "page": page, "data": [format_video_doc(d) for d in docs]}

@web.patch("/api/movies/{vid}/rating")
async def set_rating(vid: str, data: dict, user: dict = Depends(auth)):
    oid = validate_object_id(vid)
    rating = data.get("rating")
    if rating is None: raise HTTPException(400, "Missing 'rating' field")
    try: rating = float(rating)
    except (TypeError, ValueError): raise HTTPException(400, "Rating must be a number")
    if not (0 <= rating <= 10): raise HTTPException(400, "Rating must be between 0 and 10")
    result = await videos_col.update_one({"_id": oid}, {"$set": {"rating": round(rating, 1)}})
    if result.matched_count == 0: raise HTTPException(404, "Not found")
    await doc_cache.invalidate(f"id:{oid}")
    return {"ok": True, "rating": round(rating, 1)}

# ===================================================================
# STREAMING LOGIC
# ===================================================================
def _parse_range(range_header: Optional[str], file_size: int):
    start, end = 0, file_size - 1
    if range_header:
        m_suffix = re.match(r"bytes=-(\d+)$", range_header)
        if m_suffix:
            n = int(m_suffix.group(1))
            if n == 0: raise HTTPException(416, "Requested range not satisfiable")
            start, end = max(0, file_size - n), file_size - 1
        else:
            match = re.match(r"bytes=(\d+)-(\d*)", range_header)
            if match:
                start = int(match.group(1))
                if match.group(2): end = min(int(match.group(2)), file_size - 1)
    if file_size > 0 and start >= file_size: raise HTTPException(416, "Requested range not satisfiable")
    return start, end

async def _fetch_message_fresh(doc: dict):
    fetch_client = stream_client if _clients_started.get("stream") else bot_app
    if not fetch_client: raise HTTPException(503, "No MTProto client available")
    channel_id, message_id = doc.get("channel_id"), doc.get("message_id")
    if not channel_id or not message_id: raise HTTPException(400, "Missing channel_id or message_id")

    try:
        msg = await _call_with_flood_retry(fetch_client.get_messages, channel_id, message_id)
        if msg and not getattr(msg, "empty", False): return msg
    except PeerIdInvalid: pass
    except Exception as e:
        if "peer" in str(e).lower() and "invalid" in str(e).lower(): pass
        else: log.error(f"get_messages failed (tier 1): {e}")

    try:
        await fetch_client.get_chat(channel_id)
        try:
            peer = await fetch_client.resolve_peer(channel_id)
            if hasattr(peer, "access_hash") and peer.access_hash: await _save_access_hash(channel_id, peer.access_hash)
        except Exception: pass
        msg = await _call_with_flood_retry(fetch_client.get_messages, channel_id, message_id)
        if msg and not getattr(msg, "empty", False): return msg
    except Exception as e:
        log.warning(f"Tier 2 failed for channel {channel_id}: {e}")

    access_hash = doc.get("channel_access_hash") or await _get_access_hash_from_db(channel_id)
    if access_hash is None: raise HTTPException(503, f"Cannot resolve channel {channel_id}: no access_hash saved.")

    try:
        raw_channel_id = abs(channel_id) - 1000000000000
        if raw_channel_id <= 0: raise HTTPException(503, f"Channel {channel_id} is not a superchannel")
        input_channel = raw_types.InputChannel(id=raw_channel_id, access_hash=access_hash)
        r = await fetch_client.invoke(raw_functions.Channels.GetMessages(channel=input_channel, id=[raw_types.InputMessageID(id=message_id)]))
        from pyrogram import utils as pyro_utils
        messages_list = await pyro_utils.parse_messages(fetch_client, r)
        if messages_list and not getattr(messages_list[0], "empty", False): return messages_list[0]
    except HTTPException: raise
    except Exception as e:
        log.error(f"Tier 3 failed: {e}")
        raise HTTPException(503, f"All peer resolution methods failed: {e}")

    raise HTTPException(404, "Message not found or deleted")

async def _extract_file_info(msg) -> dict:
    file_id, file_size, mime_type, file_name = None, 0, "video/mp4", None
    if msg.video: file_id, file_size, mime_type, file_name = msg.video.file_id, msg.video.file_size or 0, msg.video.mime_type or "video/mp4", msg.video.file_name
    elif msg.document: file_id, file_size, mime_type, file_name = msg.document.file_id, msg.document.file_size or 0, msg.document.mime_type or "application/octet-stream", msg.document.file_name
    elif msg.audio: file_id, file_size, mime_type, file_name = msg.audio.file_id, msg.audio.file_size or 0, msg.audio.mime_type or "audio/mpeg", msg.audio.file_name
    else: raise HTTPException(404, "Message has no downloadable media or was deleted")
    if not file_id: raise HTTPException(400, "No file_id from fresh message")
    return {"file_id": file_id, "file_size": file_size, "mime_type": mime_type, "file_name": file_name}

async def _update_db_with_fresh_info(doc: dict, msg, file_info: dict):
    try:
        update_set = {"file_id": file_info["file_id"], "bot_file_id": file_info["file_id"], "file_size": file_info["file_size"], "mime_type": file_info["mime_type"], "synced_at": datetime.now(timezone.utc)}
        if file_info["file_name"]: update_set["file_name"] = file_info["file_name"]
        media = msg.video or msg.document
        if media and hasattr(media, "thumbs") and media.thumbs:
            try:
                new_thumb_id = max(media.thumbs, key=lambda t: t.width or 0).file_id
                if new_thumb_id: update_set["thumb_file_id"] = new_thumb_id
            except (ValueError, AttributeError): pass
        await videos_col.update_one({"_id": doc["_id"]}, {"$set": update_set})
        await _invalidate_video_cache(doc["_id"], doc.get("message_id"), doc.get("file_unique_id"))
    except Exception as e:
        log.warning(f"Could not update DB with fresh file_id: {e}")

async def build_stream_response(doc: dict, request: Request, force_download: bool = False, custom_filename: str = None):
    msg = await _fetch_message_fresh(doc)
    file_info = await _extract_file_info(msg)
    await _update_db_with_fresh_info(doc, msg, file_info)

    try:
        await asyncio.wait_for(_stream_semaphore.acquire(), timeout=15)
    except asyncio.TimeoutError:
        raise HTTPException(503, "Server busy — too many concurrent streams", headers={"Retry-After": "5"})

    try:
        client = _get_stream_client()
        range_header = request.headers.get("range")
        start, end = _parse_range(range_header, file_info["file_size"])
        length = end - start + 1 if file_info["file_size"] > 0 else 0
        chunk_offset, discard = start // CHUNK_SIZE, start % CHUNK_SIZE
        chunk_limit = math.ceil((length + discard) / CHUNK_SIZE) if length > 0 else 0

        filename = custom_filename or file_info["file_name"]
        if not filename:
            filename = f"{sanitize_filename(doc.get('title', 'download'))}.{get_file_extension(file_info['mime_type'])}"
        else: filename = sanitize_filename(filename)
        file_id = file_info["file_id"]
    except Exception:
        _stream_semaphore.release(); raise

    async def stream_generator():
        queue = asyncio.Queue(maxsize=max(1, READAHEAD_CHUNKS))
        cancel_event = asyncio.Event()
        state = {"file_id": file_id, "chunks_pulled": 0, "iterator": None}
        flood_state = {"retries": 0, "total_wait": 0.0}

        async def _handle_flood_wait(e: FloodWait) -> bool:
            flood_state["retries"] += 1; flood_state["total_wait"] += e.value
            if flood_state["retries"] > FLOOD_MAX_RETRIES or flood_state["total_wait"] > FLOOD_MAX_TOTAL_WAIT: return False
            await asyncio.sleep(e.value + 1); return True

        async def _refresh_file_id() -> bool:
            try:
                fresh_msg = await _fetch_message_fresh(doc)
                fresh_info = await _extract_file_info(fresh_msg)
                await _update_db_with_fresh_info(doc, fresh_msg, fresh_info)
                state["file_id"] = fresh_info["file_id"]; return True
            except Exception: return False

        async def producer():
            try:
                while not cancel_event.is_set():
                    if state["iterator"] is None:
                        offset = chunk_offset + state["chunks_pulled"]
                        remaining_limit = chunk_limit - state["chunks_pulled"] if chunk_limit > 0 else 0
                        if remaining_limit <= 0 and chunk_limit > 0: await queue.put(None); return
                        try:
                            state["iterator"] = client.stream_media(state["file_id"], limit=remaining_limit if remaining_limit > 0 else None, offset=offset)
                        except FileReferenceExpired:
                            if not await _refresh_file_id(): await queue.put(None); return
                            continue
                        except FloodWait as e:
                            if not await _handle_flood_wait(e): await queue.put(None); return
                            continue
                        except Exception: await queue.put(None); return

                    try:
                        async for chunk in state["iterator"]:
                            if cancel_event.is_set(): return
                            state["chunks_pulled"] += 1; await queue.put(chunk)
                        await queue.put(None); return
                    except FileReferenceExpired:
                        state["iterator"] = None
                        if not await _refresh_file_id(): await queue.put(None); return
                        continue
                    except FloodWait as e:
                        state["iterator"] = None
                        if not await _handle_flood_wait(e): await queue.put(None); return
                        continue
                    except Exception: await queue.put(None); return
            except asyncio.CancelledError: raise
            except Exception:
                try: queue.put_nowait(None)
                except asyncio.QueueFull: pass

        async def disconnect_watcher():
            while not cancel_event.is_set():
                try:
                    if await request.is_disconnected(): cancel_event.set(); return
                except Exception: pass
                await asyncio.sleep(2)

        producer_task, watcher_task = None, None
        try:
            producer_task = asyncio.create_task(producer())
            watcher_task = asyncio.create_task(disconnect_watcher())
            sent, first_chunk = 0, True
            deadline = asyncio.get_running_loop().time() + STREAM_WALL_CLOCK_BUDGET

            while not cancel_event.is_set():
                remaining_budget = deadline - asyncio.get_running_loop().time()
                if remaining_budget <= 0: return
                try:
                    chunk = await asyncio.wait_for(queue.get(), timeout=min(60, remaining_budget))
                except asyncio.TimeoutError:
                    if producer_task.done() and queue.empty(): return
                    if cancel_event.is_set(): return
                    continue
                except asyncio.CancelledError: return

                if chunk is None: return
                if first_chunk and discard > 0: chunk = chunk[discard:]
                first_chunk = False
                if not chunk: continue
                if length <= 0: yield chunk; sent += len(chunk); continue
                remaining = length - sent
                if len(chunk) >= remaining: yield chunk[:remaining]; return
                yield chunk; sent += len(chunk)
        except ClientDisconnect: pass
        except asyncio.CancelledError: pass
        finally:
            cancel_event.set()
            for task in [producer_task, watcher_task]:
                if task and not task.done():
                    task.cancel()
                    try: await task
                    except (asyncio.CancelledError, Exception): pass
            _stream_semaphore.release()

    headers = {"Accept-Ranges": "bytes", "Cache-Control": "public, max-age=86400"}
    if length > 0: headers["Content-Length"] = str(length)
    quoted_filename = quote(filename)
    headers["Content-Disposition"] = f"attachment; filename=\"{quoted_filename}\"; filename*=UTF-8''{quoted_filename}" if force_download else f"inline; filename=\"{quoted_filename}\""
    status_code = 206 if range_header and length > 0 else 200
    if status_code == 206: headers["Content-Range"] = f"bytes {start}-{end}/{file_info['file_size']}"

    return StreamingResponse(stream_generator(), status_code=status_code, media_type=file_info["mime_type"], headers=headers)

@web.head("/api/stream/{vid}")
async def stream_head(vid: str, user=Depends(auth)):
    doc = await _get_video_by_id(validate_object_id(vid))
    if not doc: raise HTTPException(404, "Not found")
    return Response(status_code=200, headers={"Content-Length": str(doc.get("file_size", 0)), "Accept-Ranges": "bytes", "Content-Type": doc.get("mime_type", "video/mp4")})

@web.get("/api/stream/{vid}")
async def stream_video(vid: str, request: Request, user=Depends(auth)):
    doc = await _get_video_by_id(validate_object_id(vid))
    if not doc: raise HTTPException(404, "Not found")
    return await build_stream_response(doc, request, force_download=False)

@web.get("/watch/{message_id}/{file_unique_id}")
@web.get("/watch/{message_id}/{file_unique_id}.mp4")
async def watch_permanent(message_id: int, file_unique_id: str, request: Request):
    doc = await _get_video_by_message(message_id, file_unique_id)
    if not doc: raise HTTPException(404, "Not found")
    return await build_stream_response(doc, request, force_download=False)

@web.get("/download/{message_id}/{file_unique_id}")
@web.get("/download/{message_id}/{file_unique_id}/{filename}")
async def download_permanent(message_id: int, file_unique_id: str, request: Request, filename: str = None):
    doc = await _get_video_by_message(message_id, file_unique_id)
    if not doc: raise HTTPException(404, "Not found")
    return await build_stream_response(doc, request, force_download=True, custom_filename=filename)

# ===================================================================
# URL GENERATION & VLC
# ===================================================================
@web.get("/api/video/{vid}/watch-url")
async def get_watch_url(vid: str, user=Depends(auth)):
    doc = await _get_video_by_id(validate_object_id(vid))
    if not doc: raise HTTPException(404, "Not found")
    if not BASE_URL: raise HTTPException(500, "PUBLIC_BASE_URL is not configured")
    return {"url": f"{BASE_URL}/watch/{doc['message_id']}/{doc['file_unique_id']}", "type": "stream", "permanent": True, "expires": None}

@web.get("/api/video/{vid}/download-url")
async def get_download_url(vid: str, user=Depends(auth)):
    doc = await _get_video_by_id(validate_object_id(vid))
    if not doc: raise HTTPException(404, "Not found")
    if not BASE_URL: raise HTTPException(500, "PUBLIC_BASE_URL is not configured")
    return {"url": f"{BASE_URL}/download/{doc['message_id']}/{doc['file_unique_id']}", "type": "download", "permanent": True, "expires": None}

@web.get("/api/video/{vid}/links")
async def get_all_links(vid: str, user=Depends(auth)):
    doc = await _get_video_by_id(validate_object_id(vid))
    if not doc: raise HTTPException(404, "Not found")
    if not BASE_URL: raise HTTPException(500, "PUBLIC_BASE_URL is not configured")
    mid, fuid = doc["message_id"], doc["file_unique_id"]
    return {"stream_url": f"{BASE_URL}/watch/{mid}/{fuid}", "download_url": f"{BASE_URL}/download/{mid}/{fuid}", "vlc_url": f"{BASE_URL}/api/video/{str(doc['_id'])}/vlc", "permanent": True, "expires": None, "title": doc.get("title", ""), "file_size": doc.get("file_size", 0)}

@web.get("/api/video/{vid}/vlc")
async def get_vlc_playlist(vid: str):
    doc = await _get_video_by_id(validate_object_id(vid))
    if not doc: raise HTTPException(404, "Not found")
    if not BASE_URL: raise HTTPException(500, "PUBLIC_BASE_URL is not configured")
    title = doc.get("title") or doc.get("file_name") or "Stream"
    playlist = f"#EXTM3U\n#EXTINF:-1,{title}\n#EXTVLCOPT:network-caching=1000\n{BASE_URL}/watch/{doc['message_id']}/{doc['file_unique_id']}\n"
    quoted = quote(f"{sanitize_filename(title)}.m3u")
    return Response(content=playlist.encode("utf-8"), media_type="audio/x-mpegurl", headers={"Content-Disposition": f"attachment; filename=\"{quoted}\"; filename*=UTF-8''{quoted}", "Cache-Control": "no-cache"})

# ===================================================================
# THUMBNAILS
# ===================================================================
@web.get("/api/thumb/{vid}")
async def get_thumb(vid: str):
    try: oid = ObjectId(vid)
    except (InvalidId, TypeError): raise HTTPException(404, "Not found")

    cached = thumb_cache.get(vid)
    if cached: return Response(content=cached, media_type="image/jpeg")

    doc = await _get_video_by_id(oid)
    if not doc: raise HTTPException(404, "Not found")

    try:
        await asyncio.wait_for(_thumb_semaphore.acquire(), timeout=8)
    except asyncio.TimeoutError:
        raise HTTPException(503, "Thumbnail service busy", headers={"Retry-After": "2"})

    try:
        client = _get_thumb_client()
        thumb_file_id = doc.get("thumb_file_id")
        if thumb_file_id:
            try:
                data = await asyncio.wait_for(_call_with_flood_retry(client.download_media, thumb_file_id, in_memory=True), timeout=10)
                if data:
                    content = data.read() if hasattr(data, 'read') else bytes(data)
                    if content:
                        await thumb_cache.set(vid, content)
                        return Response(content=content, media_type="image/jpeg")
            except Exception: pass

        try:
            msg = await asyncio.wait_for(_fetch_message_fresh(doc), timeout=15)
            media = msg.video or msg.document
            if media and hasattr(media, 'thumbs') and media.thumbs:
                best_thumb = max(media.thumbs, key=lambda t: t.width or 0)
                data = await asyncio.wait_for(_call_with_flood_retry(client.download_media, best_thumb, in_memory=True), timeout=10)
                if data:
                    content = data.read() if hasattr(data, 'read') else bytes(data)
                    if content:
                        await videos_col.update_one({"_id": doc["_id"]}, {"$set": {"thumb_file_id": best_thumb.file_id}})
                        await thumb_cache.set(vid, content)
                        return Response(content=content, media_type="image/jpeg")
        except Exception: pass
        raise HTTPException(404, "No thumbnail available")
    finally:
        _thumb_semaphore.release()

# ===================================================================
# USER LIST / HISTORY
# ===================================================================
def _normalize_ids(ids):
    valid = []
    for i in ids or []:
        try: valid.append(ObjectId(i))
        except (InvalidId, TypeError): continue
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
    if not await videos_col.find_one({"_id": ObjectId(vid)}, {"_id": 1}): raise HTTPException(404, "Not found")
    action = (data or {}).get("action", "toggle").lower()
    if action == "add": await users_col.update_one({"_id": user["_id"]}, {"$addToSet": {"my_list": vid}}); return {"added": True}
    if action == "remove": await users_col.update_one({"_id": user["_id"]}, {"$pull": {"my_list": vid}}); return {"added": False}
    if vid in user.get("my_list", []): await users_col.update_one({"_id": user["_id"]}, {"$pull": {"my_list": vid}}); return {"added": False}
    await users_col.update_one({"_id": user["_id"]}, {"$addToSet": {"my_list": vid}}); return {"added": True}

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
    await users_col.update_one({"_id": user["_id"]}, {"$push": {"history": {"$each": [vid], "$slice": -200}}})
    return {"ok": True}

@web.delete("/api/user/history")
async def clear_history(user: dict = Depends(auth)):
    await users_col.update_one({"_id": user["_id"]}, {"$set": {"history": []}})
    return {"ok": True}

# ===================================================================
# STATS & HEALTH
# ===================================================================
@web.get("/api/stats")
async def get_stats():
    pipeline = [{"$facet": {"total": [{"$count": "count"}], "movies": [{"$match": {"type": "movie"}}, {"$count": "count"}], "games": [{"$match": {"type": "game"}}, {"$count": "count"}], "channels": [{"$group": {"_id": "$channel_id"}}]}}]
    res = (await videos_col.aggregate(pipeline).to_list(length=1))[0] if await videos_col.aggregate(pipeline).to_list(length=1) else {}
    def _c(arr): return arr[0]["count"] if arr else 0
    return {"total_videos": _c(res.get("total", [])), "movies": _c(res.get("movies", [])), "games": _c(res.get("games", [])), "channels": len(res.get("channels", []))}

@web.get("/api/health")
async def health():
    try:
        count = await videos_col.estimated_document_count()
        active = MAX_CONCURRENT_STREAMS - _stream_semaphore._value if hasattr(_stream_semaphore, '_value') else -1
        return {"status": "ok", "videos": count, "stream_client": "user" if stream_client else ("bot" if bot_app else "none"), "base_url": BASE_URL or "not configured", "active_streams": active, "max_streams": MAX_CONCURRENT_STREAMS}
    except Exception as e:
        return JSONResponse({"status": "degraded", "error": str(e)}, status_code=503)

@web.get("/favicon.ico")
async def favicon(): return Response(status_code=204)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:web", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
