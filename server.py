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
from typing import Optional, Dict, Tuple

from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import DuplicateKeyError
from pyrogram import Client, filters
from pyrogram.types import Message
from pyrogram.errors import FloodWait
try:
    from pyrogram.errors import FileReferenceExpired, PeerIdInvalid
except ImportError:
    class FileReferenceExpired(Exception): pass
    class PeerIdInvalid(Exception): pass
from pyrogram.raw import functions as raw_functions
from pyrogram.raw import types as raw_types
try:
    from starlette.exceptions import ClientDisconnect
except ImportError:
    class ClientDisconnect(Exception): pass

from bson import ObjectId
from bson.errors import InvalidId
import bcrypt
from dotenv import load_dotenv

load_dotenv()

# ===================================================================
# Logging
# ===================================================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
log = logging.getLogger("nexstream")
logging.getLogger("pyrogram").setLevel(logging.WARNING)

class _SuppressFileRefExpired(logging.Filter):
    def filter(self, record): return "FILE_REFERENCE_EXPIRED" not in record.getMessage()

logging.getLogger("pyrogram.client").addFilter(_SuppressFileRefExpired())

class StreamAbort(Exception): pass

# ===================================================================
# Config
# ===================================================================
def _get_env_or_raise(key: str) -> str:
    v = os.getenv(key)
    if v is None or v == "": raise SystemExit(f"❌ Missing required environment variable: {key}")
    return v

MONGO_URL           = _get_env_or_raise("MONGO_URL")
BOT_TOKEN           = _get_env_or_raise("BOT_TOKEN")
TELEGRAM_API_ID     = int(_get_env_or_raise("TELEGRAM_API_ID"))
TELEGRAM_API_HASH   = _get_env_or_raise("TELEGRAM_API_HASH")
BASE_URL            = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
SESSION_STRING      = os.getenv("SESSION_STRING", "").strip()

CHANNELS_RAW = os.getenv("SYNC_CHANNELS", "")
CHANNELS = [int(ch.strip()) for ch in CHANNELS_RAW.split(",") if ch.strip()]

# Optimized for 512MB RAM on Render Free Tier
CHUNK_SIZE            = 1024 * 1024  # 1MB chunks
MAX_CONCURRENT_STREAMS = 2           # Hard limit to prevent OOM on Render
MAX_THUMB_CACHE       = 50           # Reduced cache
MAX_DOC_CACHE         = 50           # Small DB cache
READAHEAD_CHUNKS      = 1            # Only pre-fetch 1 chunk to save RAM

# ===================================================================
# Database
# ===================================================================
mongo = AsyncIOMotorClient(MONGO_URL, tz_aware=True, serverSelectionTimeoutMS=10000, maxPoolSize=10)
db = mongo.nexstream
videos_col = db.videos
users_col  = db.users

# ===================================================================
# MTProto Clients
# ===================================================================
stream_client: Optional[Client] = None
bot_app: Optional[Client] = None
_clients_started: dict = {"stream": False, "bot": False}
_stream_semaphore = asyncio.Semaphore(MAX_CONCURRENT_STREAMS)

# ===================================================================
# Caches (Memory optimized)
# ===================================================================
class BoundedCache:
    def __init__(self, max_size: int = MAX_THUMB_CACHE):
        self._max = max_size
        self._data: Dict[str, bytes] = {}
        self._lock = asyncio.Lock()

    def get(self, key: str) -> Optional[bytes]: return self._data.get(key)

    async def set(self, key: str, value: bytes):
        async with self._lock:
            if key in self._data: self._data.pop(key)
            self._data[key] = value
            while len(self._data) > self._max:
                oldest = next(iter(self._data))
                self._data.pop(oldest, None)

class DocCache:
    def __init__(self, max_size: int = MAX_DOC_CACHE, ttl: int = 300):
        self._max = max_size
        self._ttl = ttl
        self._data: OrderedDict[str, Tuple[dict, float]] = OrderedDict()
        self._lock = asyncio.Lock()

    def _expired(self, ts: float) -> bool: return (datetime.now(timezone.utc).timestamp() - ts) > self._ttl

    async def get(self, key: str) -> Optional[dict]:
        async with self._lock:
            item = self._data.get(key)
            if not item: return None
            doc, ts = item
            if self._expired(ts):
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return dict(doc)

    async def set(self, key: str, value: dict):
        async with self._lock:
            if key in self._data: self._data.pop(key)
            self._data[key] = (dict(value), datetime.now(timezone.utc).timestamp())
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    async def invalidate(self, key: str):
        async with self._lock: self._data.pop(key, None)

thumb_cache = BoundedCache(MAX_THUMB_CACHE)
doc_cache = DocCache(MAX_DOC_CACHE, ttl=300)

# ===================================================================
# Helpers
# ===================================================================
def validate_object_id(vid: str) -> ObjectId:
    try: return ObjectId(vid)
    except (InvalidId, TypeError): raise HTTPException(404, "Not found")

def hash_pw(pw: str) -> str: return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
def verify_pw(pw: str, hashed: str) -> bool:
    try: return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except: return False

def is_valid_email(email: str) -> bool: return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email))
def escape_regex(text: str) -> str: return re.escape(text)

def sanitize_filename(filename: str) -> str:
    if not filename: return "download"
    filename = re.sub(r'[\\/:*?"<>|\r\n]', '_', filename)
    if len(filename) > 200:
        name, _, ext = filename.rpartition('.')
        filename = (name[:190] + '.' + ext) if ext else filename[:200]
    return filename

def get_file_extension(mime_type: str, filename: str = "") -> str:
    if filename and '.' in filename:
        ext = filename.rsplit('.', 1)[-1]
        if ext and len(ext) <= 5: return ext.lower()
    return {"video/mp4": "mp4", "video/x-matroska": "mkv", "video/webm": "webm", "video/avi": "avi", "video/quicktime": "mov", "video/x-flv": "flv", "video/mpeg": "mpeg", "video/3gpp": "3gp", "audio/mpeg": "mp3", "audio/ogg": "ogg", "audio/wav": "wav", "application/octet-stream": "bin"}.get(mime_type, "bin")

async def get_token_from_request(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "): return auth_header[7:].strip()
    return request.query_params.get("token")

async def auth(request: Request) -> dict:
    token = await get_token_from_request(request)
    if not token: raise HTTPException(401, "Not logged in")
    user = await users_col.find_one({"token": token})
    if not user: raise HTTPException(401, "Invalid token")
    expires_at = user.get("expires_at")
    if expires_at:
        if expires_at.tzinfo is None: expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc): raise HTTPException(401, "Token expired")
    return user

async def get_video_doc(vid: str, projection: Optional[dict] = None) -> Optional[dict]:
    if projection: return await videos_col.find_one({"_id": validate_object_id(vid)}, projection)
    cached = await doc_cache.get(vid)
    if cached: return cached
    doc = await videos_col.find_one({"_id": validate_object_id(vid)})
    if doc: await doc_cache.set(vid, doc)
    return doc

# ===================================================================
# SYNC LOGIC
# ===================================================================
def _detect_type(caption: str) -> str:
    if not caption: return "movie"
    m = re.search(r"#(movie|game)s?\b", caption, re.IGNORECASE)
    return m.group(1).lower() if m else "movie"

def _parse_genres(caption: str) -> list:
    matches = re.findall(r"#genre-([\w-]+)", caption or "", re.IGNORECASE)
    seen, out = set(), []
    for g in matches:
        gl = g.lower()
        if gl not in seen: seen.add(gl); out.append(gl)
    return out

def _build_doc(message: Message) -> dict:
    media = message.video or message.document
    title = (message.caption or media.file_name or "Untitled")[:500]
    thumb_file_id = None
    if getattr(media, "thumbs", None):
        try: thumb_file_id = max(media.thumbs, key=lambda t: t.width or 0).file_id
        except: pass
    return {
        "file_unique_id": media.file_unique_id, "file_id": media.file_id, "bot_file_id": media.file_id,
        "file_name": media.file_name or "", "title": title, "desc": (message.caption or "")[:2000],
        "duration": getattr(media, "duration", 0) or 0, "width": getattr(media, "width", 0) or 0,
        "height": getattr(media, "height", 0) or 0, "file_size": media.file_size or 0,
        "mime_type": media.mime_type or "video/mp4", "thumb_file_id": thumb_file_id,
        "channel_id": message.chat.id, "message_id": message.id, "views": message.views or 0,
        "date": message.date, "type": _detect_type(message.caption), "genres": _parse_genres(message.caption),
        "year": message.date.year if message.date else datetime.now(timezone.utc).year,
        "synced_at": datetime.now(timezone.utc),
    }

async def _upsert_video(client: Client, message: Message):
    media = message.video or message.document
    if not media: return
    doc = _build_doc(message)
    try:
        peer = await client.resolve_peer(message.chat.id)
        if hasattr(peer, "access_hash"): doc["channel_access_hash"] = peer.access_hash
    except: pass
    try:
        await videos_col.update_one({"file_unique_id": doc["file_unique_id"]}, {"$set": doc, "$setOnInsert": {"rating": 0}}, upsert=True)
    except Exception as e: log.error(f"Sync fail: {e}")

def _register_sync_handlers(client: Client):
    if not CHANNELS: return
    video_filter = filters.chat(CHANNELS) & (filters.video | filters.document)
    @client.on_message(video_filter)
    async def new_media_handler(c, m): await _upsert_video(c, m)
    @client.on_edited_message(video_filter)
    async def edited_media_handler(c, m): await _upsert_video(c, m)
    @client.on_deleted_messages(filters.chat(CHANNELS))
    async def deleted_media_handler(c, messages):
        for m in messages:
            try:
                chat_id = m.chat.id if m.chat else None
                q = {"channel_id": chat_id, "message_id": m.id} if chat_id else {"message_id": m.id, "channel_id": {"$in": CHANNELS}}
                await videos_col.delete_many(q)
            except: pass

# ===================================================================
# Lifespan
# ===================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global stream_client, bot_app
    bot_app = Client("nexstream_bot", api_id=TELEGRAM_API_ID, api_hash=TELEGRAM_API_HASH, bot_token=BOT_TOKEN, in_memory=False)
    try:
        await bot_app.start(); _clients_started["bot"] = True
    except FloodWait as e:
        await asyncio.sleep(e.value + 1); await bot_app.start(); _clients_started["bot"] = True
    _register_sync_handlers(bot_app)

    if SESSION_STRING:
        try:
            stream_client = Client("nexstream_user", api_id=TELEGRAM_API_ID, api_hash=TELEGRAM_API_HASH, session_string=SESSION_STRING, in_memory=True)
            await stream_client.start(); _clients_started["stream"] = True
        except: stream_client = None

    await ensure_indexes()
    yield
    for c in (stream_client, bot_app):
        if c:
            try: await c.stop()
            except: pass

web = FastAPI(lifespan=lifespan, docs_url="/docs", redoc_url=None)
web.add_middleware(GZipMiddleware, minimum_size=1024)
web.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@web.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException): raise exc
    if isinstance(exc, StreamAbort): return Response(status_code=204, content=b"")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

async def ensure_indexes():
    try:
        await videos_col.create_index("file_unique_id", unique=True, sparse=True)
        await videos_col.create_index([("channel_id", 1), ("message_id", 1)], unique=True, name="channel_message_unique")
        await videos_col.create_index("type")
        await videos_col.create_index([("title", "text")])
        await videos_col.create_index("message_id")
        await users_col.create_index("token")
        await users_col.create_index("email", unique=True, sparse=True)
    except: pass

def format_video_doc(d: dict) -> Optional[dict]:
    if not d: return None
    d = dict(d); d["id"] = str(d.pop("_id"))
    base = BASE_URL or ""
    d["thumb_url"] = f"{base}/api/thumb/{d['id']}" if d.get("thumb_file_id") else ""
    if d.get("message_id") and d.get("file_unique_id"):
        d["stream_url"] = f"{base}/watch/{d['message_id']}/{d['file_unique_id']}"
        d["download_url"] = f"{base}/download/{d['message_id']}/{d['file_unique_id']}"
    else: d["stream_url"] = ""; d["download_url"] = ""
    if not d.get("genres"): d["genres"] = []
    if d.get("type") not in ("movie", "game"): d["type"] = "movie"
    return d

def _get_stream_client() -> Client:
    if stream_client and _clients_started["stream"]: return stream_client
    if bot_app and _clients_started["bot"]: return bot_app
    raise HTTPException(503, "Streaming service not available")

# ===================================================================
# AUTH ROUTES
# ===================================================================
@web.post("/api/auth/register")
async def register(data: dict):
    name, email, pw = str(data.get("name", "")).strip(), str(data.get("email", "")).strip().lower(), str(data.get("password", ""))
    if not name or not is_valid_email(email) or len(pw) < 6: raise HTTPException(400, "Invalid input")
    token = secrets.token_hex(32)
    hashed = await asyncio.get_running_loop().run_in_executor(None, hash_pw, pw)
    try:
        await users_col.insert_one({"name": name, "email": email, "password": hashed, "token": token, "expires_at": datetime.now(timezone.utc) + timedelta(days=30), "my_list": [], "history": []})
    except DuplicateKeyError: raise HTTPException(400, "Email already exists")
    return {"token": token, "name": name, "email": email}

@web.post("/api/auth/login")
async def login(data: dict):
    email, pw = str(data.get("email", "")).strip().lower(), str(data.get("password", ""))
    user = await users_col.find_one({"email": email})
    if not user: raise HTTPException(401, "Wrong email or password")
    if not await asyncio.get_running_loop().run_in_executor(None, verify_pw, pw, user["password"]): raise HTTPException(401, "Wrong email or password")
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
@web.get("/api/movies")
async def get_movies(page: int = 1, limit: int = 20, genre: str = ""):
    q = {"type": "movie"}
    if genre and genre.lower() != "all": q["genres"] = {"$in": [genre.lower()]}
    docs = await videos_col.find(q).sort("date", -1).skip((page - 1) * limit).limit(limit).to_list(length=limit)
    return {"total": await videos_col.count_documents(q), "page": page, "data": [format_video_doc(d) for d in docs]}

@web.get("/api/games")
async def get_games(page: int = 1, limit: int = 20, genre: str = ""):
    q = {"type": "game"}
    if genre and genre.lower() != "all": q["genres"] = {"$in": [genre.lower()]}
    docs = await videos_col.find(q).sort("date", -1).skip((page - 1) * limit).limit(limit).to_list(length=limit)
    return {"total": await videos_col.count_documents(q), "page": page, "data": [format_video_doc(d) for d in docs]}

@web.get("/api/movies/{vid}")
async def get_movie(vid: str):
    doc = await get_video_doc(vid)
    if not doc: raise HTTPException(404, "Not found")
    return format_video_doc(doc)

@web.get("/api/search")
async def search(q: str = "", page: int = 1, limit: int = 20):
    if not q or len(q) < 2: return {"total": 0, "page": page, "data": []}
    q_filter = {"title": {"$regex": escape_regex(q), "$options": "i"}}
    docs = await videos_col.find(q_filter).sort("date", -1).skip((page - 1) * limit).limit(limit).to_list(length=limit)
    return {"total": await videos_col.count_documents(q_filter), "page": page, "data": [format_video_doc(d) for d in docs]}

# ===================================================================
# STREAMING LOGIC (Robust & Fast for Render)
# ===================================================================
def _parse_range(range_header: str, file_size: int):
    start, end = 0, file_size - 1
    if range_header:
        m_suffix = re.match(r"bytes=-(\d+)$", range_header)
        if m_suffix:
            n = int(m_suffix.group(1))
            if n == 0: raise HTTPException(416, "Requested range not satisfiable")
            start = max(0, file_size - n)
        else:
            match = re.match(r"bytes=(\d+)-(\d*)", range_header)
            if match:
                start = int(match.group(1))
                if match.group(2): end = min(int(match.group(2)), file_size - 1)
    if start >= file_size: raise HTTPException(416, "Requested range not satisfiable")
    return start, end

async def _fetch_message_fresh(doc: dict, max_retries: int = 1):
    fetch_client = stream_client if stream_client and _clients_started["stream"] else (bot_app if bot_app and _clients_started["bot"] else None)
    if not fetch_client: raise HTTPException(503, "No MTProto client available")
    channel_id, message_id = doc.get("channel_id"), doc.get("message_id")
    if not channel_id or not message_id: raise HTTPException(400, "Missing channel_id or message_id")

    for attempt in range(max_retries + 1):
        try: return await fetch_client.get_messages(channel_id, message_id)
        except PeerIdInvalid: pass
        except FileReferenceExpired: pass
        except FloodWait as e: await asyncio.sleep(min(e.value + 1, 10))
        except Exception as e:
            if "peer" not in str(e).lower() or "invalid" not in str(e).lower(): break

        try:
            await fetch_client.resolve_peer(channel_id)
            msg = await fetch_client.get_messages(channel_id, message_id)
            if msg: return msg
        except: pass

        access_hash = doc.get("channel_access_hash")
        if access_hash is not None:
            try:
                input_channel = raw_types.InputChannel(id=abs(channel_id) - 1000000000000, access_hash=access_hash)
                r = await fetch_client.invoke(raw_functions.channels.GetMessages(channel=input_channel, id=[raw_types.InputMessageID(id=message_id)]))
                from pyrogram import utils as pyro_utils
                msgs = await pyro_utils.parse_messages(fetch_client, r)
                if msgs: return msgs[0]
            except: pass
        if attempt < max_retries: await asyncio.sleep(0.5)
    raise HTTPException(503, "Failed to fetch message")

async def _extract_file_info(msg) -> dict:
    media = msg.video or msg.document or msg.audio
    if not media: raise HTTPException(400, "Message has no downloadable media")
    if not media.file_id or not media.file_size: raise HTTPException(400, "Invalid file data")
    return {"file_id": media.file_id, "file_size": media.file_size, "mime_type": media.mime_type or "video/mp4", "file_name": media.file_name}

async def _readahead_stream(client: Client, file_id: str, chunk_offset: int, chunk_limit: int, request: Request, discard: int, length: int, doc: dict):
    """Highly optimized streamer with 1 chunk read-ahead to save RAM."""
    queue = asyncio.Queue(maxsize=READAHEAD_CHUNKS + 1)
    producer_done = asyncio.Event()
    refresh_attempted = False

    async def producer():
        nonlocal refresh_attempted
        current_file_id, offset, remaining = file_id, chunk_offset, chunk_limit
        try:
            while remaining > 0:
                if await request.is_disconnected(): break
                try:
                    async for chunk in client.stream_media(current_file_id, limit=remaining, offset=offset):
                        if await request.is_disconnected(): return
                        if chunk:
                            await queue.put(chunk)
                            offset += 1; remaining -= 1
                            if remaining <= 0: break
                    break # Natural exhaustion
                except FileReferenceExpired:
                    if refresh_attempted: return
                    refresh_attempted = True
                    try:
                        fresh_msg = await _fetch_message_fresh(doc, max_retries=1)
                        current_file_id = (await _extract_file_info(fresh_msg))["file_id"]
                        continue # Retry with same offset
                    except: return
                except FloodWait as e: await asyncio.sleep(min(e.value + 1, 10)); continue
                except: return
        finally:
            producer_done.set()
            try: queue.put_nowait(None)
            except: pass

    producer_task = asyncio.create_task(producer())
    sent = 0
    try:
        while True:
            if await request.is_disconnected(): break
            get_task = asyncio.create_task(queue.get())
            done_task = asyncio.create_task(producer_done.wait())
            done, pending = await asyncio.wait({get_task, done_task}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending: t.cancel()

            if get_task in done: chunk = get_task.result()
            else:
                try: chunk = queue.get_nowait()
                except: break

            if chunk is None: break
            if sent == 0 and discard > 0: chunk = chunk[discard:]
            if not chunk: continue
            
            remaining = length - sent
            if len(chunk) >= remaining:
                yield chunk[:remaining]
                return
            yield chunk
            sent += len(chunk)
    except ClientDisconnect: pass
    finally:
        if not producer_task.done(): producer_task.cancel()

async def build_stream_response(doc: dict, request: Request, force_download: bool = False, custom_filename: str = None):
    msg = await _fetch_message_fresh(doc)
    file_info = await _extract_file_info(msg)
    
    # Update DB in background
    asyncio.create_task(videos_col.update_one({"_id": doc["_id"]}, {"$set": {"file_id": file_info["file_id"], "synced_at": datetime.now(timezone.utc)}}))

    client = _get_stream_client()
    range_header = request.headers.get("range")
    start, end = _parse_range(range_header, file_info["file_size"])
    length = end - start + 1
    chunk_offset = start // CHUNK_SIZE
    discard = start % CHUNK_SIZE
    chunk_limit = math.ceil((length + discard) / CHUNK_SIZE)

    filename = sanitize_filename(custom_filename or file_info["file_name"] or f"{doc.get('title', 'download')}.{get_file_extension(file_info['mime_type'])}")
    
    async def stream_generator():
        try:
            async with _stream_semaphore:
                async for chunk in _readahead_stream(client, file_info["file_id"], chunk_offset, chunk_limit, request, discard, length, doc):
                    yield chunk
        except: pass

    headers = {"Accept-Ranges": "bytes", "Content-Length": str(length), "Cache-Control": "public, max-age=86400"}
    quoted_filename = quote(filename)
    headers["Content-Disposition"] = f'attachment; filename="{quoted_filename}"' if force_download else f'inline; filename="{quoted_filename}"'
    
    status_code = 206 if range_header else 200
    if range_header: headers["Content-Range"] = f"bytes {start}-{end}/{file_info['file_size']}"

    return StreamingResponse(stream_generator(), status_code=status_code, media_type=file_info["mime_type"], headers=headers)

# ===================================================================
# STREAMING ENDPOINTS
# ===================================================================
@web.get("/api/stream/{vid}")
async def stream_video(vid: str, request: Request, user=Depends(auth)):
    doc = await get_video_doc(vid)
    if not doc: raise HTTPException(404, "Not found")
    return await build_stream_response(doc, request)

@web.get("/watch/{message_id}/{file_unique_id}")
async def watch_permanent(message_id: int, file_unique_id: str, request: Request):
    doc = await videos_col.find_one({"message_id": message_id, "file_unique_id": file_unique_id})
    if not doc: raise HTTPException(404, "Not found")
    return await build_stream_response(doc, request)

@web.get("/download/{message_id}/{file_unique_id}")
async def download_permanent(message_id: int, file_unique_id: str, request: Request, filename: str = None):
    doc = await videos_col.find_one({"message_id": message_id, "file_unique_id": file_unique_id})
    if not doc: raise HTTPException(404, "Not found")
    return await build_stream_response(doc, request, force_download=True, custom_filename=filename)

@web.get("/api/thumb/{vid}")
async def get_thumb(vid: str):
    cached = thumb_cache.get(vid)
    if cached: return Response(content=cached, media_type="image/jpeg")
    doc = await get_video_doc(vid, projection={"thumb_file_id": 1, "channel_id": 1, "message_id": 1, "channel_access_hash": 1})
    if not doc: raise HTTPException(404, "Not found")
    try:
        msg = await _fetch_message_fresh(doc)
        media = msg.video or msg.document
        thumb_file_id = max(media.thumbs, key=lambda t: t.width or 0).file_id if media and media.thumbs else None
        if not thumb_file_id: raise HTTPException(404, "No thumbnail")
    except: raise HTTPException(503, "Thumbnail unavailable")

    async def stream_thumb():
        buffer = io.BytesIO()
        async for chunk in bot_app.stream_media(thumb_file_id):
            if chunk: buffer.write(chunk); yield chunk
        await thumb_cache.set(vid, buffer.getvalue())
    return StreamingResponse(stream_thumb(), media_type="image/jpeg")

@web.get("/api/health")
async def health(): return {"status": "ok", "stream_client": "user" if stream_client else "bot"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:web", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
