import os
import re
import math
import hmac
import secrets
import time
import asyncio
import logging
from pymongo.errors import DuplicateKeyError
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Depends, Response, Query
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pyrogram import Client
from bson import ObjectId
from bson.errors import InvalidId
import bcrypt
from dotenv import load_dotenv

load_dotenv()

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("nexstream")

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
def _get_env_or_raise(key):
    value = os.getenv(key)
    if value is None:
        raise SystemExit(f"❌ Missing required environment variable: {key}")
    return value

MONGO_URL = _get_env_or_raise("MONGO_URL")
BASE_URL = os.getenv("PUBLIC_BASE_URL", "")
TELEGRAM_API_ID = int(_get_env_or_raise("TELEGRAM_API_ID"))
TELEGRAM_API_HASH = _get_env_or_raise("TELEGRAM_API_HASH")

STREAM_SECRET = os.getenv("STREAM_SECRET")
if not STREAM_SECRET:
    log.warning("STREAM_SECRET not set! Signed watch URLs will break on server restart.")
    STREAM_SECRET = secrets.token_hex(32)

CHUNK = 1024 * 1024  # 1 MB

# -------------------------------------------------------------------
# Database (async Motor)
# -------------------------------------------------------------------
mongo = AsyncIOMotorClient(MONGO_URL)
db = mongo.nexstream
videos_col = db.videos
users_col = db.users
sessions_col = db.sessions

# -------------------------------------------------------------------
# Pyrogram client (global with async lock)
# -------------------------------------------------------------------
pyro: Optional[Client] = None
_pyro_lock = asyncio.Lock()

async def get_pyro():
    global pyro
    async with _pyro_lock:
        if pyro is None or not pyro.is_connected:
            session_data = await sessions_col.find_one({"name": "main"})
            if not session_data or not session_data.get("string"):
                raise HTTPException(500, "No Telegram session. Run sync.py first.")

            # Clean up dead client if it exists
            if pyro is not None:
                try:
                    await pyro.stop()
                except Exception:
                    pass

            # Create a fresh client
            pyro = Client(
                "render",
                api_id=TELEGRAM_API_ID,
                api_hash=TELEGRAM_API_HASH,
                session_string=session_data["string"],
                no_updates=True,
                in_memory=True,
            )
            await pyro.start()
    return pyro

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def validate_object_id(vid: str) -> ObjectId:
    try:
        return ObjectId(vid)
    except InvalidId:
        raise HTTPException(404, "Not found")

def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_pw(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode('utf-8'), hashed.encode('utf-8'))

def is_valid_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def escape_regex(text: str) -> str:
    return re.escape(text)

async def get_token_from_request(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    token = request.query_params.get("token")
    if token:
        return token
    return None

async def auth(request: Request):
    token = await get_token_from_request(request)
    if not token:
        raise HTTPException(401, "Not logged in")
    user = await users_col.find_one({"token": token})
    if not user:
        raise HTTPException(401, "Invalid token")
    if user.get("expires_at") and user["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(401, "Token expired")
    return user

# -------------------------------------------------------------------
# CORS & Lifespan
# -------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    await ensure_indexes()
    log.info("NexStream API starting up...")
    log.info("BASE_URL: %s", BASE_URL or "(not set)")
    yield
    global pyro
    if pyro and pyro.is_connected:
        await pyro.stop()
        log.info("Pyrogram client disconnected")

web = FastAPI(lifespan=lifespan)

web.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# Indexes
# -------------------------------------------------------------------
async def ensure_indexes():
    try:
        await videos_col.create_index("file_unique_id", unique=True, sparse=True)
        await videos_col.create_index([("channel_id", 1), ("message_id", 1)])
        await videos_col.create_index("type")
        await videos_col.create_index([("title", "text")])
        await users_col.create_index("token")
        await users_col.create_index("email", unique=True, sparse=True)
        log.info("Database indexes ensured")
    except Exception as e:
        log.warning("Could not ensure indexes: %s", e)

# -------------------------------------------------------------------
# Format video doc
# -------------------------------------------------------------------
def format_video_doc(d: dict) -> dict:
    if d is None:
        return None
    d = dict(d)
    d["id"] = str(d.pop("_id"))
    # Always append api/thumb if file_id exists, frontend will handle local prepends
    d["thumb_url"] = d.get("thumb_url") or (
        f"{BASE_URL}/api/thumb/{d['thumb_file_id']}" if d.get("thumb_file_id") else ""
    )
    return d

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
    if await users_col.find_one({"email": email}):
        raise HTTPException(400, "Email already exists")
    
    token = secrets.token_hex(32)
    hashed = hash_pw(pw)
    expires = datetime.now(timezone.utc) + timedelta(days=30)
    
    try:
        await users_col.insert_one({
            "name": name,
            "email": email,
            "password": hashed,
            "token": token,
            "expires_at": expires,
            "my_list": [],
            "history": [],
            "created_at": datetime.now(timezone.utc)
        })
    except DuplicateKeyError:
        raise HTTPException(400, "Email already exists")
        
    return {"token": token, "name": name, "email": email}
    
@web.post("/api/auth/login")
async def login(data: dict):
    email = str(data.get("email", "")).strip().lower()
    pw = str(data.get("password", ""))
    user = await users_col.find_one({"email": email})
    if not user or not verify_pw(pw, user["password"]):
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

# -------------------------------------------------------------------
# MOVIES / GAMES / SEARCH
# -------------------------------------------------------------------
@web.get("/api/movies")
async def get_movies(page: int = 1, limit: int = 20, genre: str = ""):
    page = max(1, page)
    limit = min(100, max(1, limit))
    q = {"type": "movie"}
    if genre and genre != "All":
        q["genres"] = {"$in": [genre]}
    total = await videos_col.count_documents(q)
    docs = await videos_col.find(q).sort("date", -1).skip((page - 1) * limit).limit(limit).to_list(None)
    return {"total": total, "page": page, "data": [format_video_doc(d) for d in docs]}

@web.get("/api/games")
async def get_games(page: int = 1, limit: int = 20, genre: str = ""):
    page = max(1, page)
    limit = min(100, max(1, limit))
    q = {"type": "game"}
    if genre and genre != "All":
        q["genres"] = {"$in": [genre]}
    total = await videos_col.count_documents(q)
    docs = await videos_col.find(q).sort("date", -1).skip((page - 1) * limit).limit(limit).to_list(None)
    return {"total": total, "page": page, "data": [format_video_doc(d) for d in docs]}

@web.get("/api/movies/{vid}")
async def get_movie(vid: str):
    oid = validate_object_id(vid)
    doc = await videos_col.find_one({"_id": oid})
    if not doc:
        raise HTTPException(404, "Not found")
    return format_video_doc(doc)

@web.get("/api/search")
async def search(q: str = "", page: int = 1, limit: int = 20):
    if not q or len(q) < 2:
        return {"total": 0, "data": []}
    page = max(1, page)
    limit = min(100, max(1, limit))
    q_filter = {"title": {"$regex": escape_regex(q), "$options": "i"}}
    total = await videos_col.count_documents(q_filter)
    docs = await videos_col.find(q_filter).sort("date", -1).skip((page - 1) * limit).limit(limit).to_list(None)
    return {"total": total, "page": page, "data": [format_video_doc(d) for d in docs]}

# -------------------------------------------------------------------
# STREAMING (authenticated)
# -------------------------------------------------------------------
@web.head("/api/stream/{vid}")
async def stream_head(vid: str, user=Depends(auth)):
    oid = validate_object_id(vid)
    doc = await videos_col.find_one({"_id": oid})
    if not doc:
        raise HTTPException(404)
    return Response(
        status_code=200,
        headers={
            "Content-Length": str(doc["file_size"]),
            "Accept-Ranges": "bytes",
            "Content-Type": doc.get("mime_type", "video/mp4"),
        }
    )

@web.get("/api/stream/{vid}")
async def stream_video(vid: str, request: Request, user=Depends(auth)):
    oid = validate_object_id(vid)
    doc = await videos_col.find_one({"_id": oid})
    if not doc:
        raise HTTPException(404, "Not found")
    file_size = doc["file_size"]
    p = await get_pyro()

    range_header = request.headers.get("range")
    if range_header:
        m = re.match(r"bytes=(\d+)-(\d*)", range_header)
        if not m:
            raise HTTPException(416, "Invalid range")
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else file_size - 1
        end = min(end, file_size - 1)
        if start >= file_size:
            raise HTTPException(416, "Range not satisfiable")
        length = end - start + 1
        chunk_offset = start // CHUNK
        discard = start % CHUNK   
        chunk_limit = math.ceil((length + discard) / CHUNK)

        async def gen():
            sent = 0
            try:
                # FIXED: Pyrogram requires a message object or string file_id, not a tuple
                async for chunk in p.stream_media(
                    doc["file_id"],
                    offset=chunk_offset,
                    limit=chunk_limit,
                ):
                    if sent == 0 and discard > 0:
                        chunk = chunk[discard:]
                    if not chunk:
                        continue
                    if sent + len(chunk) > length:
                        yield chunk[: length - sent]
                        break
                    yield chunk
                    sent += len(chunk)
            except Exception as e:
                log.error("stream error: %s", e)

        return StreamingResponse(
            gen(),
            status_code=206,
            media_type=doc.get("mime_type", "video/mp4"),
            headers={
                "Content-Range": f"bytes {start}-{end}/{file_size}",
                "Accept-Ranges": "bytes",
                "Content-Length": str(length),
                "Cache-Control": "public, max-age=86400",
            },
        )
    else:
        async def gen_full():
            try:
                # FIXED: Pyrogram requires a string file_id
                async for chunk in p.stream_media(doc["file_id"]):
                    yield chunk
            except Exception as e:
                log.error("full stream error: %s", e)

        return StreamingResponse(
            gen_full(),
            media_type=doc.get("mime_type", "video/mp4"),
            headers={
                "Content-Length": str(file_size),
                "Accept-Ranges": "bytes",
            },
        )

# -------------------------------------------------------------------
# SIGNED WATCH-URL
# -------------------------------------------------------------------
def generate_stream_token(vid: str) -> str:
    expiry = int(time.time()) + 3600
    raw = f"{vid}:{expiry}"
    sig = hmac.new(STREAM_SECRET.encode(), raw.encode(), "sha256").hexdigest()[:8]
    return f"{sig}{expiry}"

@web.get("/api/video/{vid}/watch-url")
async def get_watch_url(vid: str, user=Depends(auth)):
    oid = validate_object_id(vid)
    doc = await videos_col.find_one({"_id": oid}, {"message_id": 1, "file_unique_id": 1})
    if not doc:
        raise HTTPException(404, "Not found")

    token = generate_stream_token(str(doc["_id"]))
    url = f"{BASE_URL}/watch/{doc['message_id']}/{doc['file_unique_id']}.mp4?hash={token}"
    return {"url": url}

@web.get("/watch/{message_id}/{file_unique_id}.mp4")
async def watch_hashed(
    message_id: int,
    file_unique_id: str,
    request: Request,
    sig_hash: str = Query("", alias="hash"),
):
    doc = await videos_col.find_one({
        "message_id": message_id,
        "file_unique_id": file_unique_id
    })
    if not doc:
        raise HTTPException(404)

    try:
        expiry = int(sig_hash[8:]) if len(sig_hash) > 8 else 0
        sig = sig_hash[:8]
        raw = f"{str(doc['_id'])}:{expiry}"
        expected = hmac.new(STREAM_SECRET.encode(), raw.encode(), "sha256").hexdigest()[:8]
        if sig != expected or time.time() > expiry:
            raise HTTPException(403, "Invalid or expired link")
    except HTTPException:
        raise               
    except Exception:
        raise HTTPException(403, "Invalid hash") 

    file_size = doc["file_size"]
    p = await get_pyro()
    range_header = request.headers.get("range")
    
    if range_header:
        m = re.match(r"bytes=(\d+)-(\d*)", range_header)
        if not m:
            raise HTTPException(416)
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else file_size - 1
        end = min(end, file_size - 1)
        if start >= file_size:
            raise HTTPException(416)
        length = end - start + 1
        chunk_offset = start // CHUNK
        discard = start % CHUNK   
        chunk_limit = math.ceil((length + discard) / CHUNK)

        async def gen():
            sent = 0
            try:
                # FIXED: Pyrogram requires a string file_id
                async for chunk in p.stream_media(
                    doc["file_id"],
                    offset=chunk_offset,
                    limit=chunk_limit,
                ):
                    if sent == 0 and discard > 0:
                        chunk = chunk[discard:]
                    if not chunk:
                        continue
                    if sent + len(chunk) > length:
                        yield chunk[: length - sent]
                        break
                    yield chunk
                    sent += len(chunk)
            except Exception as e:
                log.error("hashed stream error: %s", e)

        return StreamingResponse(
            gen(),
            status_code=206,
            media_type=doc.get("mime_type", "video/mp4"),
            headers={
                "Content-Range": f"bytes {start}-{end}/{file_size}",
                "Accept-Ranges": "bytes",
                "Content-Length": str(length),
            },
        )
    else:
        async def gen_full():
            try:
                # FIXED: Pyrogram requires a string file_id
                async for chunk in p.stream_media(doc["file_id"]):
                    yield chunk
            except Exception as e:
                log.error("hashed full stream error: %s", e)

        return StreamingResponse(
            gen_full(),
            media_type=doc.get("mime_type", "video/mp4"),
            headers={
                "Content-Length": str(file_size),
                "Accept-Ranges": "bytes",
            },
        )

# -------------------------------------------------------------------
# THUMBNAILS
# -------------------------------------------------------------------
@web.get("/api/thumb/{file_id}")
async def get_thumb(file_id: str):
    if not file_id or len(file_id) < 10:
        raise HTTPException(404)
    try:
        p = await get_pyro()
        data = await p.download_media(file_id, in_memory=True)
        if data:
            content = data.read() if hasattr(data, 'read') else bytes(data)
            return Response(content=content, media_type="image/jpeg")
    except Exception as e:
        log.error("thumb error: %s", e)
    raise HTTPException(404)

# -------------------------------------------------------------------
# USER LIST / HISTORY
# -------------------------------------------------------------------
@web.get("/api/user/list")
async def get_list(user: dict = Depends(auth)) -> list[dict]:
    ids = user.get("my_list", [])
    if not ids:
        return []
    valid_ids = []
    for i in ids:
        try:
            valid_ids.append(ObjectId(i))
        except InvalidId:
            continue
    if not valid_ids:
        return []
    oids = valid_ids
    docs = await videos_col.find({"_id": {"$in": oids}}).to_list(None)
    order = {i: idx for idx, i in enumerate(ids)}
    docs.sort(key=lambda x: order.get(str(x["_id"]), 9999))
    return [format_video_doc(d) for d in docs]

@web.post("/api/user/list/{vid}")
async def toggle_list(vid: str, user: dict = Depends(auth)) -> dict[str, bool]:
    oid = validate_object_id(vid)
    if not await videos_col.find_one({"_id": oid}):
        raise HTTPException(404, "Video not found")
    current = user.get("my_list", [])
    if vid in current:
        await users_col.update_one({"_id": user["_id"]}, {"$pull": {"my_list": vid}})
        return {"added": False}
    await users_col.update_one({"_id": user["_id"]}, {"$addToSet": {"my_list": vid}})
    return {"added": True}

@web.get("/api/user/history")
async def get_history(user: dict = Depends(auth)) -> list[dict]:
    ids = user.get("history", [])
    if not ids:
        return []
    valid_ids = []
    for i in ids:
        try:
            valid_ids.append(ObjectId(i))
        except InvalidId:
            continue
    if not valid_ids:
        return []
    oids = valid_ids
    docs = await videos_col.find({"_id": {"$in": oids}}).to_list(None)
    order = {i: idx for idx, i in enumerate(reversed(ids))}
    docs.sort(key=lambda x: order.get(str(x["_id"]), 9999))
    return [format_video_doc(d) for d in docs]

@web.post("/api/user/history/{vid}")
async def add_history(vid: str, user: dict = Depends(auth)) -> dict[str, bool]:
    validate_object_id(vid)
    await users_col.update_one({"_id": user["_id"]}, {"$pull": {"history": vid}})
    await users_col.update_one(
        {"_id": user["_id"]},
        {"$push": {"history": {"$each": [vid], "$slice": -200}}}
    )
    return {"ok": True}

@web.delete("/api/user/history")
async def clear_history(user: dict = Depends(auth)) -> dict[str, bool]:
    try:
        await users_col.update_one(
            {"_id": user["_id"]},
            {"$set": {"history": []}}
        )
        return {"ok": True}
    except Exception as e:
        log.error("Failed to clear history: %s", e)
        raise HTTPException(500, "Database error")

# -------------------------------------------------------------------
# CHANNELS & STATS
# -------------------------------------------------------------------
@web.get("/api/channels")
async def get_channels():
    pipeline = [
        {"$group": {"_id": "$channel_id", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$project": {"channel_id": "$_id", "count": 1, "_id": 0}}
    ]
    return await videos_col.aggregate(pipeline).to_list(None)

@web.get("/api/stats")
async def get_stats():
    try:
        pipeline = [
            {
                "$facet": {
                    "total": [{"$count": "count"}],
                    "movies": [{"$match": {"type": "movie"}}, {"$count": "count"}],
                    "games": [{"$match": {"type": "game"}}, {"$count": "count"}],
                    "with_thumbs": [{"$match": {"thumb_url": {"$regex": "^http"}}}, {"$count": "count"}],
                    "channels": [{"$group": {"_id": "$channel_id"}}]
                }
            }
        ]
        results = await videos_col.aggregate(pipeline).to_list(1)
        if not results:
            return {"total_videos": 0, "movies": 0, "games": 0, "with_thumbnails": 0, "channels": 0}
        result = results[0]
        return {
            "total_videos": result["total"][0]["count"] if result["total"] else 0,
            "movies": result["movies"][0]["count"] if result["movies"] else 0,
            "games": result["games"][0]["count"] if result["games"] else 0,
            "with_thumbnails": result["with_thumbs"][0]["count"] if result["with_thumbs"] else 0,
            "channels": len(result["channels"]),
        }
    except Exception as e:
        log.error("Stats error: %s", e)
        raise HTTPException(500, "Failed to get stats")

# -------------------------------------------------------------------
# HEALTH
# -------------------------------------------------------------------
@web.get("/api/health")
async def health():
    try:
        count = await videos_col.estimated_document_count()
        return {"status": "ok", "videos": count}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "error", "error": str(e)})

@web.get("/")
async def root():
    return {"message": "NexStream API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:web", host="0.0.0.0", port=8000, reload=True)
