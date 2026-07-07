import os, re, hashlib, secrets, json, asyncio
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pyrogram import Client, errors
from dotenv import load_dotenv
from bson import ObjectId

load_dotenv()

web = FastAPI()

web.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allows all frontend domains to access the API
    allow_credentials=True,
    allow_methods=["*"], # Allows GET, POST, PUT, DELETE, etc.
    allow_headers=["*"], # Allows Authorization headers (Bearer tokens)
)

mongo = MongoClient(os.getenv("MONGO_URL"))
db = mongo.nexstream
videos_col = db.videos
users_col = db.users
sessions_col = db.sessions  # 存储Pyrogram session

pyro = None

async def get_pyro():
    global pyro
    if pyro is None:
        # 从MongoDB加载session
        session_data = sessions_col.find_one({"name": "main"})
        if not session_data or not session_data.get("string"):
            raise HTTPException(500, "No Telegram session. Run sync.py first on your PC to save session.")

        pyro = Client(
            "render_session",
            api_id=int(os.getenv("TELEGRAM_API_ID")),
            api_hash=os.getenv("TELEGRAM_API_HASH"),
            session_string=session_data["string"]
        )
        await pyro.start()
    return pyro

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def auth(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(401, "Not logged in")
    user = users_col.find_one({"token": token})
    if not user:
        raise HTTPException(401, "Invalid token")
    return user

# ========== AUTH ==========
@web.post("/api/auth/register")
async def register(data: dict):
    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    pw = data.get("password", "")
    if not name or not email or len(pw) < 4:
        raise HTTPException(400, "Invalid input")
    if users_col.find_one({"email": email}):
        raise HTTPException(400, "Email exists")
    token = secrets.token_hex(32)
    users_col.insert_one({
        "name": name, "email": email,
        "password": hash_pw(pw), "token": token,
        "my_list": [], "history": [],
        "created_at": datetime.utcnow()
    })
    return {"token": token, "name": name, "email": email}

@web.post("/api/auth/login")
async def login(data: dict):
    email = data.get("email", "").strip().lower()
    pw = data.get("password", "")
    user = users_col.find_one({"email": email, "password": hash_pw(pw)})
    if not user:
        raise HTTPException(401, "Wrong email or password")
    token = secrets.token_hex(32)
    users_col.update_one({"_id": user["_id"]}, {"$set": {"token": token}})
    return {"token": token, "name": user["name"], "email": user["email"]}

@web.post("/api/auth/telegram")
async def tg_login(data: dict):
    tg_id = str(data.get("tg_id", ""))
    name = data.get("name", "User")
    if not tg_id:
        raise HTTPException(400, "Missing tg_id")
    user = users_col.find_one({"tg_id": tg_id})
    token = secrets.token_hex(32)
    if user:
        users_col.update_one({"_id": user["_id"]}, {"$set": {"token": token, "name": name}})
    else:
        users_col.insert_one({
            "tg_id": tg_id, "name": name,
            "email": f"tg_{tg_id}@local",
            "password": hash_pw(secrets.token_hex(16)),
            "token": token, "my_list": [], "history": [],
            "created_at": datetime.utcnow()
        })
    return {"token": token, "name": name}

@web.get("/api/auth/me")
async def me(user=Depends(auth)):
    return {"name": user["name"], "email": user["email"]}

# ========== MOVIES ==========
@web.get("/api/movies")
async def get_movies(page: int = 1, limit: int = 20, genre: str = ""):
    q = {"type": "movie"}
    if genre and genre != "All":
        q["genres"] = genre
    total = videos_col.count_documents(q)
    docs = list(videos_col.find(q).sort("date", -1).skip((page-1)*limit).limit(limit))
    for d in docs:
        d["id"] = str(d["_id"])
        d["thumb_url"] = f"/api/thumb/{d.get('thumb_file_id','')}" if d.get('thumb_file_id') else ""
        del d["_id"]
    return {"total": total, "page": page, "data": docs}

@web.get("/api/games")
async def get_games(page: int = 1, limit: int = 20, genre: str = ""):
    q = {"type": "game"}
    if genre and genre != "All":
        q["genres"] = genre
    total = videos_col.count_documents(q)
    docs = list(videos_col.find(q).sort("date", -1).skip((page-1)*limit).limit(limit))
    for d in docs:
        d["id"] = str(d["_id"])
        d["thumb_url"] = f"/api/thumb/{d.get('thumb_file_id','')}" if d.get('thumb_file_id') else ""
        del d["_id"]
    return {"total": total, "page": page, "data": docs}

@web.get("/api/movies/{vid}")
async def get_movie(vid: str):
    d = videos_col.find_one({"_id": ObjectId(vid)})
    if not d:
        raise HTTPException(404, "Not found")
    d["id"] = str(d["_id"])
    d["thumb_url"] = f"/api/thumb/{d.get('thumb_file_id','')}" if d.get('thumb_file_id') else ""
    del d["_id"]
    # 不要把file_id发给前端，只给stream URL
    d["stream_url"] = f"/api/stream/{vid}"
    return d

# ========== STREAMING ==========
@web.get("/api/stream/{vid}")
async def stream_video(vid: str, request: Request):
    d = videos_col.find_one({"_id": ObjectId(vid)})
    if not d:
        raise HTTPException(404, "Not found")

    file_size = d.get("file_size", 0)
    if not file_size:
        raise HTTPException(500, "Unknown file size")

    range_header = request.headers.get("range")

    try:
        p = await get_pyro()
    except Exception as e:
        raise HTTPException(503, f"Telegram client error: {str(e)}")

    if range_header:
        m = re.match(r"bytes=(\d+)-(\d*)", range_header)
        if not m:
            raise HTTPException(416, "Bad range")
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else file_size - 1
        if start >= file_size or end >= file_size:
            raise HTTPException(416, "Range not satisfiable")
        length = end - start + 1

        async def gen():
            try:
                async for chunk in p.download_media(
                    d["file_id"],
                    offset=start,
                    limit=length,
                    in_memory=True
                ):
                    yield chunk
            except Exception:
                pass

        return StreamingResponse(gen(), status_code=206, media_type="video/mp4",
            headers={
                "Content-Range": f"bytes {start}-{end}/{file_size}",
                "Accept-Ranges": "bytes",
                "Content-Length": str(length),
                "Cache-Control": "public, max-age=86400"
            })
    else:
        async def gen_full():
            try:
                async for chunk in p.download_media(d["file_id"], in_memory=True):
                    yield chunk
            except Exception:
                pass

        return StreamingResponse(gen_full(), media_type="video/mp4",
            headers={"Content-Length": str(file_size), "Accept-Ranges": "bytes"})

# ========== THUMBNAILS ==========
@web.get("/api/thumb/{file_id}")
async def get_thumb(file_id: str):
    if not file_id or file_id in ("None", "undefined", "null"):
        raise HTTPException(404)
    try:
        p = await get_pyro()
        data = await p.download_media(file_id, in_memory=True)
        if data:
            content = data.read() if hasattr(data, 'read') else bytes(data)
            return Response(content=content, media_type="image/jpeg")
    except Exception:
        pass
    raise HTTPException(404)

# ========== SEARCH ==========
@web.get("/api/search")
async def search(q: str = "", page: int = 1, limit: int = 20):
    if not q or len(q) < 2:
        return {"total": 0, "data": []}
    q2 = {"title": {"$regex": q, "$options": "i"}}
    total = videos_col.count_documents(q2)
    docs = list(videos_col.find(q2).sort("date", -1).skip((page-1)*limit).limit(limit))
    for d in docs:
        d["id"] = str(d["_id"])
        d["thumb_url"] = f"/api/thumb/{d.get('thumb_file_id','')}" if d.get('thumb_file_id') else ""
        del d["_id"]
    return {"total": total, "page": page, "data": docs}

# ========== CHANNELS ==========
@web.get("/api/channels")
async def get_channels():
    pipeline = [
        {"$group": {"_id": "$channel_id", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    return list(videos_col.aggregate(pipeline))

# ========== USER LIST / HISTORY ==========
@web.get("/api/user/list")
async def get_list(user=Depends(auth)):
    ids = user.get("my_list", [])
    if not ids:
        return []
    docs = list(videos_col.find({"_id": {"$in": [ObjectId(i) for i in ids]}}))
    for d in docs:
        d["id"] = str(d["_id"])
        del d["_id"]
    return docs

@web.post("/api/user/list/{vid}")
async def toggle_list(vid: str, user=Depends(auth)):
    if vid in user.get("my_list", []):
        users_col.update_one({"_id": user["_id"]}, {"$pull": {"my_list": vid}})
        return {"added": False}
    users_col.update_one({"_id": user["_id"]}, {"$addToSet": {"my_list": vid}})
    return {"added": True}

@web.get("/api/user/history")
async def get_history(user=Depends(auth)):
    ids = user.get("history", [])
    if not ids:
        return []
    docs = list(videos_col.find({"_id": {"$in": [ObjectId(i) for i in ids]}}))
    order = {v: i for i, v in enumerate(reversed(ids))}
    docs.sort(key=lambda x: order.get(str(x["_id"]), 9999))
    for d in docs:
        d["id"] = str(d["_id"])
        del d["_id"]
    return docs

@web.post("/api/user/history/{vid}")
async def add_history(vid: str, user=Depends(auth)):
    # 最多保留200条历史
    users_col.update_one({"_id": user["_id"]}, {
        "$addToSet": {"history": vid},
        "$set": {"history": user.get("history", [])[-199:] + [vid]}
    })
    return {"ok": True}

# ========== HEALTH ==========
@web.get("/api/health")
async def health():
    try:
        count = videos_col.count_documents({})
        return {"status": "ok", "videos": count, "ram": "ok"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
