from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Annotated
from passlib.context import CryptContext
from jose import JWTError, jwt
import os
import logging
import uuid
import secrets
from pathlib import Path
from dotenv import load_dotenv
from enum import Enum
from whatsapp_service import UltraMSGService

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
security = HTTPBearer()

app = FastAPI(title="WhatsApp Multi-Agent Router CRM", version="1.0.0")
api_router = APIRouter(prefix="/api")

# Initialize WhatsApp service
whatsapp_service = UltraMSGService(db)

# Enums
class UserRole(str, Enum):
    SUPERUSER = "SUPERUSER"
    ADMIN = "ADMIN"
    AGENT = "AGENT"

class LeadStatus(str, Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    COMPLETED = "completed"

class AssignmentStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    EXPIRED = "expired"
    REASSIGNED = "reassigned"

class Priority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

# Pydantic Models
class UserBase(BaseModel):
    email: EmailStr
    name: str
    role: UserRole
    is_active: bool = True

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: UserRole
    tenant_id: Optional[str]
    is_active: bool
    created_at: datetime

class TenantBase(BaseModel):
    name: str
    plan: str = "basic"

class TenantCreate(TenantBase):
    pass

class WhatsAppConfig(BaseModel):
    provider: str = "ultramsg"
    api_base: Optional[str] = None
    api_key: Optional[str] = None
    phone_number: Optional[str] = None

class Tenant(TenantBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    wa_config: Optional[WhatsAppConfig] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class TenantResponse(BaseModel):
    id: str
    name: str
    plan: str
    wa_config: Optional[WhatsAppConfig]
    created_at: datetime

class CustomerInfo(BaseModel):
    name: str
    phone: str
    email: Optional[str] = None

class LeadBase(BaseModel):
    external_lead_id: str
    source: str
    customer: CustomerInfo
    journey_stage: str = "new"
    priority: Priority = Priority.MEDIUM
    metadata: Dict[str, Any] = {}

class LeadCreate(LeadBase):
    callback_url: Optional[str] = None

class Lead(LeadBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    status: LeadStatus = LeadStatus.PENDING
    assigned_agent_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class LeadResponse(BaseModel):
    id: str
    tenant_id: str
    external_lead_id: str
    source: str
    customer: CustomerInfo
    journey_stage: str
    priority: Priority
    status: LeadStatus
    assigned_agent_id: Optional[str]
    metadata: Dict[str, Any]
    created_at: datetime

class AssignmentBase(BaseModel):
    lead_id: str
    agent_id: str

class Assignment(AssignmentBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    status: AssignmentStatus = AssignmentStatus.PENDING
    assigned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=10))
    accepted_at: Optional[datetime] = None

class AssignmentResponse(BaseModel):
    id: str
    tenant_id: str
    lead_id: str
    agent_id: str
    status: AssignmentStatus
    assigned_at: datetime
    expires_at: datetime
    accepted_at: Optional[datetime]

# Token Models
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse

class TokenData(BaseModel):
    username: Optional[str] = None
    tenant_id: Optional[str] = None
    role: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

# Utility Functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        tenant_id: str = payload.get("tenant_id")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username, tenant_id=tenant_id)
    except JWTError:
        raise credentials_exception
    
    user = await db.users.find_one({"email": token_data.username})
    if user is None:
        raise credentials_exception
    return User(**user)

def require_role(required_roles: List[UserRole]):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user
    return role_checker

# Database helpers
def prepare_for_mongo(data):
    """Convert Pydantic model to MongoDB document format"""
    if isinstance(data, dict):
        # Convert id to _id for MongoDB
        if 'id' in data:
            data['_id'] = data.pop('id')
        
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
            elif isinstance(value, dict):
                data[key] = prepare_for_mongo(value)
    return data

def parse_from_mongo(item):
    """Convert MongoDB document to Pydantic-compatible format"""
    if isinstance(item, dict):
        # Convert MongoDB _id to id
        if '_id' in item:
            item['id'] = item.pop('_id')
        
        for key, value in item.items():
            if isinstance(value, str) and key.endswith('_at'):
                try:
                    item[key] = datetime.fromisoformat(value.replace('Z', '+00:00'))
                except:
                    pass
            elif isinstance(value, dict):
                item[key] = parse_from_mongo(value)
    return item

# Authentication Routes
@api_router.post("/auth/register", response_model=UserResponse)
async def register_user(
    user_data: UserCreate,
    current_user: User = Depends(require_role([UserRole.SUPERUSER, UserRole.ADMIN]))
):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Role validation based on current user
    if current_user.role == UserRole.ADMIN and user_data.role not in [UserRole.ADMIN, UserRole.AGENT]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins can only create ADMIN or AGENT users"
        )
    
    # Hash password
    hashed_password = get_password_hash(user_data.password)
    
    # Create user object
    user_dict = user_data.dict()
    user_dict.pop('password')
    user_dict['password_hash'] = hashed_password
    
    # Set tenant_id for non-superusers
    if user_data.role != UserRole.SUPERUSER:
        user_dict['tenant_id'] = current_user.tenant_id
    
    user = User(**user_dict)
    user_dict = prepare_for_mongo(user.dict())
    
    # Insert to database
    await db.users.insert_one(user_dict)
    
    return UserResponse(**user.dict())

@api_router.post("/auth/login", response_model=Token)
async def login(login_data: LoginRequest):
    # Find user
    user_doc = await db.users.find_one({"email": login_data.email})
    if not user_doc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    user_doc = parse_from_mongo(user_doc)
    
    # Verify password
    if not verify_password(login_data.password, user_doc['password_hash']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    # Check if user is active
    if not user_doc.get('is_active', True):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated"
        )
    
    # Create tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token_data = {
        "sub": user_doc['email'],
        "tenant_id": user_doc.get('tenant_id'),
        "role": user_doc['role']
    }
    
    access_token = create_access_token(
        data=token_data, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(data=token_data)
    
    user_response = UserResponse(**user_doc)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": user_response
    }

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse(**current_user.dict())

# Tenant Management Routes
@api_router.post("/tenants", response_model=TenantResponse)
async def create_tenant(
    tenant_data: TenantCreate,
    current_user: User = Depends(require_role([UserRole.SUPERUSER]))
):
    tenant = Tenant(**tenant_data.dict())
    tenant_dict = prepare_for_mongo(tenant.dict())
    
    await db.tenants.insert_one(tenant_dict)
    return TenantResponse(**tenant.dict())

@api_router.get("/tenants", response_model=List[TenantResponse])
async def get_tenants(
    current_user: User = Depends(require_role([UserRole.SUPERUSER]))
):
    tenants = await db.tenants.find().to_list(1000)
    return [TenantResponse(**parse_from_mongo(tenant)) for tenant in tenants]

# Lead Management Routes
@api_router.post("/leads", response_model=Dict[str, Any])
async def create_lead(
    lead_data: LeadCreate,
    x_tenant_id: Annotated[str, Header()] = None,
    current_user: User = Depends(get_current_user) if True else None
):
    # Allow both external API calls (with X-Tenant-Id) and authenticated calls
    if x_tenant_id:
        # External API call (from Luciana AI)
        tenant_id = x_tenant_id
    elif current_user and (current_user.role in [UserRole.ADMIN, UserRole.SUPERUSER]):
        # Authenticated call (manual creation)
        tenant_id = current_user.tenant_id if current_user.role == UserRole.ADMIN else None
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Tenant-Id header required or admin authentication needed"
        )
    
    # Check if tenant exists
    tenant = await db.tenants.find_one({"_id": tenant_id})
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found"
        )
    
    # Create lead
    lead_dict = lead_data.dict()
    lead_dict['tenant_id'] = tenant_id
    lead = Lead(**lead_dict)
    lead_dict = prepare_for_mongo(lead.dict())
    
    await db.leads.insert_one(lead_dict)
    
    # Try to assign lead to an agent (automatic)
    assignment_result = await assign_lead_to_agent(lead.id, tenant_id)
    
    return {
        "status": "queued",
        "router_lead_id": lead.id,
        "assignment_state": assignment_result.get("status", "pending")
    }

@api_router.post("/leads/manual", response_model=Dict[str, Any])
async def create_lead_manual(
    lead_data: LeadCreate,
    assigned_agent_id: Optional[str] = None,
    current_user: User = Depends(require_role([UserRole.ADMIN, UserRole.SUPERUSER]))
):
    """Create lead manually with optional specific agent assignment"""
    
    # Get the correct tenant_id
    if current_user.role == UserRole.ADMIN:
        tenant_id = current_user.tenant_id
    else:  # SUPERUSER
        # For superuser, we need to get tenant_id from context or require it
        # For now, let's assume superuser operations require a specific tenant
        if not current_user.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Tenant ID required for this operation"
            )
        tenant_id = current_user.tenant_id
    
    # Create lead
    lead_dict = lead_data.dict()
    lead_dict['tenant_id'] = tenant_id
    lead = Lead(**lead_dict)
    
    if assigned_agent_id:
        # Verify agent exists and belongs to tenant
        agent = await db.users.find_one({
            "_id": assigned_agent_id,
            "tenant_id": tenant_id,
            "role": UserRole.AGENT,
            "is_active": True
        })
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found or inactive"
            )
        
        lead.assigned_agent_id = assigned_agent_id
        lead.status = LeadStatus.ASSIGNED
    
    lead_dict = prepare_for_mongo(lead.dict())
    await db.leads.insert_one(lead_dict)
    
    # Create assignment if agent specified
    if assigned_agent_id:
        assignment = Assignment(
            tenant_id=tenant_id,
            lead_id=lead.id,
            agent_id=assigned_agent_id,
            status=AssignmentStatus.PENDING
        )
        assignment_dict = prepare_for_mongo(assignment.dict())
        await db.assignments.insert_one(assignment_dict)
        
        return {
            "status": "created",
            "lead_id": lead.id,
            "assignment_state": "assigned_to_specific_agent",
            "agent_id": assigned_agent_id
        }
    else:
        # Auto-assign using round-robin
        assignment_result = await assign_lead_to_agent(lead.id, tenant_id)
        return {
            "status": "created",
            "lead_id": lead.id,
            "assignment_state": assignment_result.get("status", "pending")
        }

@api_router.patch("/leads/{lead_id}/assign")
async def reassign_lead(
    lead_id: str,
    agent_id: str,
    current_user: User = Depends(require_role([UserRole.ADMIN, UserRole.SUPERUSER]))
):
    """Manually reassign lead to specific agent"""
    
    # Find lead
    lead = await db.leads.find_one({"_id": lead_id})
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")
    
    # Get tenant_id for verification
    tenant_id = current_user.tenant_id if current_user.role == UserRole.ADMIN else lead["tenant_id"]
    
    # Verify agent
    agent = await db.users.find_one({
        "_id": agent_id,
        "tenant_id": tenant_id,
        "role": UserRole.AGENT,
        "is_active": True
    })
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Update lead
    await db.leads.update_one(
        {"_id": lead_id},
        {
            "$set": {
                "assigned_agent_id": agent_id,
                "status": LeadStatus.ASSIGNED
            }
        }
    )
    
    # Cancel existing assignments
    await db.assignments.update_many(
        {"lead_id": lead_id, "status": AssignmentStatus.PENDING},
        {"$set": {"status": AssignmentStatus.REASSIGNED}}
    )
    
    # Create new assignment
    assignment = Assignment(
        tenant_id=tenant_id,
        lead_id=lead_id,
        agent_id=agent_id,
        status=AssignmentStatus.PENDING
    )
    assignment_dict = prepare_for_mongo(assignment.dict())
    await db.assignments.insert_one(assignment_dict)
    
    return {"message": "Lead reassigned successfully", "agent_id": agent_id}

async def assign_lead_to_agent(lead_id: str, tenant_id: str):
    """Simple round-robin assignment logic"""
    # Find available agents in the tenant
    agents = await db.users.find({
        "tenant_id": tenant_id,
        "role": UserRole.AGENT,
        "is_active": True
    }).to_list(1000)
    
    if not agents:
        return {"status": "no_agents_available"}
    
    # Simple round-robin: get agent with least assignments
    agent_assignments = {}
    for agent in agents:
        count = await db.assignments.count_documents({
            "agent_id": agent["_id"],
            "status": {"$in": [AssignmentStatus.PENDING, AssignmentStatus.ACCEPTED]}
        })
        agent_assignments[agent["_id"]] = count
    
    # Select agent with minimum assignments
    selected_agent_id = min(agent_assignments.keys(), key=lambda k: agent_assignments[k])
    
    # Create assignment
    assignment = Assignment(
        tenant_id=tenant_id,
        lead_id=lead_id,
        agent_id=selected_agent_id
    )
    assignment_dict = prepare_for_mongo(assignment.dict())
    
    await db.assignments.insert_one(assignment_dict)
    
    # Update lead status
    await db.leads.update_one(
        {"_id": lead_id},
        {"$set": {"status": LeadStatus.ASSIGNED, "assigned_agent_id": selected_agent_id}}
    )
    
    return {"status": "assigned", "assignment_id": assignment.id, "agent_id": selected_agent_id}

@api_router.get("/leads", response_model=List[LeadResponse])
async def get_leads(
    current_user: User = Depends(get_current_user)
):
    query = {}
    
    # Filter by tenant for non-superusers
    if current_user.role != UserRole.SUPERUSER:
        query["tenant_id"] = current_user.tenant_id
    
    # Agents only see their assigned leads
    if current_user.role == UserRole.AGENT:
        query["assigned_agent_id"] = current_user.id
    
    leads = await db.leads.find(query).to_list(1000)
    return [LeadResponse(**parse_from_mongo(lead)) for lead in leads]

# Assignment Management Routes
@api_router.get("/assignments", response_model=List[AssignmentResponse])
async def get_assignments(
    current_user: User = Depends(get_current_user)
):
    query = {}
    
    # Filter by tenant for non-superusers
    if current_user.role != UserRole.SUPERUSER:
        query["tenant_id"] = current_user.tenant_id
    
    # Agents only see their assignments
    if current_user.role == UserRole.AGENT:
        query["agent_id"] = current_user.id
    
    logger.info(f"Assignment query for {current_user.email}: {query}")
    
    assignments = await db.assignments.find(query).to_list(1000)
    logger.info(f"Found {len(assignments)} assignments")
    
    parsed_assignments = []
    for assignment in assignments:
        try:
            parsed = parse_from_mongo(assignment)
            logger.info(f"Parsed assignment: {parsed.get('id', 'NO_ID')[:8]}... status={parsed.get('status')}")
            parsed_assignments.append(AssignmentResponse(**parsed))
        except Exception as e:
            logger.error(f"Error parsing assignment {assignment.get('_id', 'NO_ID')}: {e}")
    
    return parsed_assignments

@api_router.post("/assignments/{assignment_id}/accept")
async def accept_assignment(
    assignment_id: str,
    current_user: User = Depends(require_role([UserRole.AGENT]))
):
    # Find assignment
    assignment = await db.assignments.find_one({"_id": assignment_id, "agent_id": current_user.id})
    if not assignment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assignment not found"
        )
    
    if assignment["status"] != AssignmentStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Assignment is no longer pending"
        )
    
    # Update assignment
    await db.assignments.update_one(
        {"_id": assignment_id},
        {
            "$set": {
                "status": AssignmentStatus.ACCEPTED,
                "accepted_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    
    # Update lead
    await db.leads.update_one(
        {"_id": assignment["lead_id"]},
        {"$set": {"status": LeadStatus.ACCEPTED}}
    )
    
    return {"message": "Assignment accepted successfully"}

@api_router.post("/assignments/{assignment_id}/decline")
async def decline_assignment(
    assignment_id: str,
    current_user: User = Depends(require_role([UserRole.AGENT]))
):
    # Find assignment
    assignment = await db.assignments.find_one({"_id": assignment_id, "agent_id": current_user.id})
    if not assignment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assignment not found"
        )
    
    if assignment["status"] != AssignmentStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Assignment is no longer pending"
        )
    
    # Update assignment
    await db.assignments.update_one(
        {"_id": assignment_id},
        {"$set": {"status": AssignmentStatus.DECLINED}}
    )
    
    # Try to reassign to another agent
    await assign_lead_to_agent(assignment["lead_id"], assignment["tenant_id"])
    
    return {"message": "Assignment declined successfully"}

# User Management Routes
@api_router.get("/users", response_model=List[UserResponse])
async def get_users(
    current_user: User = Depends(require_role([UserRole.SUPERUSER, UserRole.ADMIN]))
):
    query = {}
    
    # Admins only see users from their tenant
    if current_user.role == UserRole.ADMIN:
        query["tenant_id"] = current_user.tenant_id
    
    users = await db.users.find(query).to_list(1000)
    return [UserResponse(**parse_from_mongo(user)) for user in users]

# WhatsApp Configuration Models
class WhatsAppConfigUpdate(BaseModel):
    api_base: str = "https://api.ultramsg.com/instance123456"  # Example URL
    api_key: str
    phone_number: str

class SendMessageRequest(BaseModel):
    to_phone: str
    message: str
    type: str = "text"

class WebhookData(BaseModel):
    id: str
    type: str
    from_: str = Field(alias="from")
    body: Optional[str] = None
    timestamp: int
    instance: Optional[str] = None
    media_url: Optional[str] = None

# WhatsApp Configuration Routes
@api_router.patch("/whatsapp/config")
async def update_whatsapp_config(
    config: WhatsAppConfigUpdate,
    current_user: User = Depends(require_role([UserRole.ADMIN]))
):
    """Update WhatsApp configuration for the tenant"""
    
    # Update tenant's WhatsApp config
    await db.tenants.update_one(
        {"_id": current_user.tenant_id},
        {
            "$set": {
                "wa_config": {
                    "provider": "ultramsg",
                    "api_base": config.api_base,
                    "api_key": config.api_key,
                    "phone_number": config.phone_number
                }
            }
        }
    )
    
    return {"message": "WhatsApp configuration updated successfully"}

@api_router.get("/whatsapp/status")
async def get_whatsapp_status(
    current_user: User = Depends(require_role([UserRole.ADMIN]))
):
    """Get WhatsApp instance status"""
    
    status_result = await whatsapp_service.get_instance_status(current_user.tenant_id)
    return status_result

@api_router.post("/whatsapp/send-message")
async def send_whatsapp_message(
    message_request: SendMessageRequest,
    current_user: User = Depends(require_role([UserRole.ADMIN, UserRole.AGENT]))
):
    """Send WhatsApp message"""
    
    if message_request.type == "text":
        result = await whatsapp_service.send_text_message(
            current_user.tenant_id,
            message_request.to_phone,
            message_request.message
        )
    else:
        return {"success": False, "error": "Message type not supported yet"}
    
    return result

# WhatsApp Webhook Route (no auth required)
@api_router.post("/webhooks/whatsapp")
async def whatsapp_webhook(request: Request):
    """Receive WhatsApp webhooks from UltraMSG"""
    
    try:
        body = await request.body()
        webhook_data = await request.json()
        
        # Process the incoming message
        result = await whatsapp_service.process_incoming_message(webhook_data)
        
        return {"status": "received", "processed": result.get("success", False)}
        
    except Exception as e:
        logger.error(f"Webhook processing error: {e}")
        return {"status": "error", "message": str(e)}

# Conversation and Message Models
class MessageBase(BaseModel):
    text: Optional[str] = None
    type: str = "text"
    media_url: Optional[str] = None

class MessageCreate(MessageBase):
    conversation_id: str

class Message(MessageBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    lead_id: str
    conversation_id: Optional[str] = None
    direction: str = "out"  # "in" or "out"
    whatsapp_message_id: Optional[str] = None
    sent_by_agent_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class MessageResponse(BaseModel):
    id: str
    text: Optional[str]
    type: str
    direction: str
    whatsapp_message_id: Optional[str]
    sent_by_agent_id: Optional[str]
    created_at: datetime

# Conversation Routes
@api_router.get("/conversations/{lead_id}/messages", response_model=List[MessageResponse])
async def get_conversation_messages(
    lead_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get messages for a conversation"""
    
    # Verify user can access this lead
    lead = await db.leads.find_one({"_id": lead_id})
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")
    
    # Check permissions
    if current_user.role == UserRole.AGENT and lead.get("assigned_agent_id") != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to view this conversation")
    
    if current_user.role != UserRole.SUPERUSER and lead.get("tenant_id") != current_user.tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized to view this conversation")
    
    # Get messages
    messages = await db.messages.find({"lead_id": lead_id}).sort("created_at", 1).to_list(1000)
    return [MessageResponse(**parse_from_mongo(message)) for message in messages]

@api_router.post("/conversations/{lead_id}/messages")
async def send_conversation_message(
    lead_id: str,
    message: MessageBase,
    current_user: User = Depends(require_role([UserRole.AGENT]))
):
    """Send message in a conversation"""
    
    # Verify user can send to this lead
    lead = await db.leads.find_one({"_id": lead_id, "assigned_agent_id": current_user.id})
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found or not assigned to you")
    
    # Send via WhatsApp
    result = await whatsapp_service.send_text_message(
        current_user.tenant_id,
        lead["customer"]["phone"],
        message.text
    )
    
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to send message"))
    
    # Save message to database
    message_data = Message(
        tenant_id=current_user.tenant_id,
        lead_id=lead_id,
        text=message.text,
        type=message.type,
        direction="out",
        whatsapp_message_id=result.get("message_id"),
        sent_by_agent_id=current_user.id
    )
    
    message_dict = prepare_for_mongo(message_data.dict())
    await db.messages.insert_one(message_dict)
    
    return MessageResponse(**message_data.dict())

# Include router in app
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