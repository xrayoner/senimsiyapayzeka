from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends, Cookie
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
from emergentintegrations.llm.chat import LlmChat, UserMessage
import bcrypt
import jwt
import httpx

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Define Models
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    name: str
    picture: Optional[str] = None
    password_hash: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserSession(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    user_id: str
    session_token: str
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Message(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    conversation_id: str
    user_id: str
    role: str
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Conversation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    title: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Request/Response Models
class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str

class LoginRequest(BaseModel):
    email: str
    password: str

class GoogleAuthRequest(BaseModel):
    session_id: str

class ConversationCreate(BaseModel):
    title: str = "Yeni Sohbet"

class ChatRequest(BaseModel):
    conversation_id: str
    message: str

class AuthResponse(BaseModel):
    user: User
    token: str

# Auth Helper Functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(request: Request) -> User:
    # Check cookie first
    token = request.cookies.get('session_token')
    
    # Fallback to Authorization header
    if not token:
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        # Check if it's a session token from Google OAuth
        session = await db.user_sessions.find_one({"session_token": token})
        if session:
            if datetime.fromisoformat(session['expires_at']) < datetime.now(timezone.utc):
                raise HTTPException(status_code=401, detail="Session expired")
            
            user_doc = await db.users.find_one({"id": session['user_id']}, {"_id": 0})
            if not user_doc:
                raise HTTPException(status_code=401, detail="User not found")
            
            if isinstance(user_doc.get('created_at'), str):
                user_doc['created_at'] = datetime.fromisoformat(user_doc['created_at'])
            return User(**user_doc)
        
        # Try JWT token
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload['user_id']
        
        user_doc = await db.users.find_one({"id": user_id}, {"_id": 0})
        if not user_doc:
            raise HTTPException(status_code=401, detail="User not found")
        
        if isinstance(user_doc.get('created_at'), str):
            user_doc['created_at'] = datetime.fromisoformat(user_doc['created_at'])
        return User(**user_doc)
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Auth Routes
@api_router.post("/auth/register", response_model=AuthResponse)
async def register(request: RegisterRequest, response: Response):
    # Check if user exists
    existing_user = await db.users.find_one({"email": request.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        email=request.email,
        name=request.name,
        password_hash=hash_password(request.password)
    )
    
    user_doc = user.model_dump()
    user_doc['created_at'] = user_doc['created_at'].isoformat()
    await db.users.insert_one(user_doc)
    
    # Create token
    token = create_jwt_token(user.id)
    
    # Set cookie
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=7*24*60*60,
        path="/"
    )
    
    # Remove password hash from response
    user.password_hash = None
    return AuthResponse(user=user, token=token)

@api_router.post("/auth/login", response_model=AuthResponse)
async def login(request: LoginRequest, response: Response):
    # Find user
    user_doc = await db.users.find_one({"email": request.email})
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Verify password
    if not user_doc.get('password_hash') or not verify_password(request.password, user_doc['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if isinstance(user_doc.get('created_at'), str):
        user_doc['created_at'] = datetime.fromisoformat(user_doc['created_at'])
    
    # Remove _id from doc
    user_doc.pop('_id', None)
    user = User(**user_doc)
    
    # Create token
    token = create_jwt_token(user.id)
    
    # Set cookie
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=7*24*60*60,
        path="/"
    )
    
    user.password_hash = None
    return AuthResponse(user=user, token=token)

@api_router.post("/auth/google", response_model=AuthResponse)
async def google_auth(request: GoogleAuthRequest, response: Response):
    # Get session data from Emergent auth service
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
                headers={"X-Session-ID": request.session_id},
                timeout=10.0
            )
            resp.raise_for_status()
            session_data = resp.json()
        except Exception as e:
            logging.error(f"Google auth error: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid session ID")
    
    email = session_data['email']
    name = session_data['name']
    picture = session_data.get('picture')
    session_token = session_data['session_token']
    
    # Check if user exists
    user_doc = await db.users.find_one({"email": email})
    
    if user_doc:
        # User exists, don't update
        if isinstance(user_doc.get('created_at'), str):
            user_doc['created_at'] = datetime.fromisoformat(user_doc['created_at'])
        user_doc.pop('_id', None)
        user = User(**user_doc)
    else:
        # Create new user
        user = User(email=email, name=name, picture=picture)
        user_doc = user.model_dump()
        user_doc['created_at'] = user_doc['created_at'].isoformat()
        await db.users.insert_one(user_doc)
    
    # Store session
    user_session = UserSession(
        user_id=user.id,
        session_token=session_token,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7)
    )
    session_doc = user_session.model_dump()
    session_doc['expires_at'] = session_doc['expires_at'].isoformat()
    session_doc['created_at'] = session_doc['created_at'].isoformat()
    await db.user_sessions.insert_one(session_doc)
    
    # Set cookie
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=7*24*60*60,
        path="/"
    )
    
    user.password_hash = None
    return AuthResponse(user=user, token=session_token)

@api_router.get("/auth/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)):
    current_user.password_hash = None
    return current_user

@api_router.post("/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get('session_token')
    if token:
        # Delete session from database
        await db.user_sessions.delete_one({"session_token": token})
    
    # Clear cookie
    response.delete_cookie(key="session_token", path="/")
    return {"message": "Logged out"}

# Protected Routes
@api_router.get("/")
async def root():
    return {"message": "Senimsi Yapay Zeka API"}

@api_router.post("/conversations", response_model=Conversation)
async def create_conversation(input: ConversationCreate, current_user: User = Depends(get_current_user)):
    conversation = Conversation(title=input.title, user_id=current_user.id)
    doc = conversation.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.conversations.insert_one(doc)
    return conversation

@api_router.get("/conversations", response_model=List[Conversation])
async def get_conversations(current_user: User = Depends(get_current_user)):
    conversations = await db.conversations.find(
        {"user_id": current_user.id}, 
        {"_id": 0}
    ).sort("timestamp", -1).to_list(100)
    
    for conv in conversations:
        if isinstance(conv['timestamp'], str):
            conv['timestamp'] = datetime.fromisoformat(conv['timestamp'])
    return conversations

@api_router.get("/conversations/{conversation_id}/messages", response_model=List[Message])
async def get_messages(conversation_id: str, current_user: User = Depends(get_current_user)):
    # Verify conversation belongs to user
    conversation = await db.conversations.find_one({"id": conversation_id, "user_id": current_user.id})
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    messages = await db.messages.find(
        {"conversation_id": conversation_id}, 
        {"_id": 0}
    ).sort("timestamp", 1).to_list(1000)
    
    for msg in messages:
        if isinstance(msg['timestamp'], str):
            msg['timestamp'] = datetime.fromisoformat(msg['timestamp'])
    return messages

@api_router.delete("/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str, current_user: User = Depends(get_current_user)):
    # Verify conversation belongs to user
    result = await db.conversations.delete_one({"id": conversation_id, "user_id": current_user.id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    # Delete all messages
    await db.messages.delete_many({"conversation_id": conversation_id})
    return {"message": "Conversation deleted"}

@api_router.post("/chat", response_model=Message)
async def chat(request: ChatRequest, current_user: User = Depends(get_current_user)):
    try:
        # Verify conversation belongs to user
        conversation = await db.conversations.find_one({"id": request.conversation_id, "user_id": current_user.id})
        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found")
        
        # Save user message
        user_message = Message(
            conversation_id=request.conversation_id,
            user_id=current_user.id,
            role="user",
            content=request.message
        )
        user_doc = user_message.model_dump()
        user_doc['timestamp'] = user_doc['timestamp'].isoformat()
        await db.messages.insert_one(user_doc)
        
        # Initialize LLM Chat
        api_key = os.environ.get('EMERGENT_LLM_KEY')
        chat_client = LlmChat(
            api_key=api_key,
            session_id=request.conversation_id,
            system_message="Sen Türkçe konuşan, yardımsever ve akıllı bir yapay zeka asistanısın. Adın 'Senimsi Yapay Zeka'. Kullanıcılara net, anlaşılır ve dostça cevaplar veriyorsun."
        ).with_model("gemini", "gemini-2.5-pro")
        
        # Prepare user message
        user_msg = UserMessage(text=request.message)
        
        # Get AI response
        ai_response = await chat_client.send_message(user_msg)
        
        # Save AI response
        assistant_message = Message(
            conversation_id=request.conversation_id,
            user_id=current_user.id,
            role="assistant",
            content=ai_response
        )
        assistant_doc = assistant_message.model_dump()
        assistant_doc['timestamp'] = assistant_doc['timestamp'].isoformat()
        await db.messages.insert_one(assistant_doc)
        
        # Update conversation title if it's the first message
        messages_count = await db.messages.count_documents({"conversation_id": request.conversation_id})
        if messages_count == 2:  # User message + AI response
            title = request.message[:50] + ("..." if len(request.message) > 50 else "")
            await db.conversations.update_one(
                {"id": request.conversation_id},
                {"$set": {"title": title}}
            )
        
        return assistant_message
        
    except Exception as e:
        logging.error(f"Chat error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()