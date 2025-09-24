#!/usr/bin/env python3
"""
Script to initialize demo data for WhatsApp CRM
"""

import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from datetime import datetime, timezone
import uuid

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def init_demo_data():
    # Connect to MongoDB
    mongo_url = "mongodb://localhost:27017"
    client = AsyncIOMotorClient(mongo_url)
    db = client["whatsapp_crm"]
    
    # Clear existing data
    print("Clearing existing data...")
    await db.users.delete_many({})
    await db.tenants.delete_many({})
    await db.leads.delete_many({})
    await db.assignments.delete_many({})
    
    # Create demo tenant
    print("Creating demo tenant...")
    tenant_id = str(uuid.uuid4())
    tenant = {
        "_id": tenant_id,
        "name": "Luciana AI Technology",
        "plan": "enterprise",
        "wa_config": {
            "provider": "ultramsg",
            "api_base": None,
            "api_key": None,
            "phone_number": None
        },
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.tenants.insert_one(tenant)
    
    # Create demo users
    print("Creating demo users...")
    
    users = [
        {
            "_id": str(uuid.uuid4()),
            "tenant_id": None,  # SUPERUSER has no tenant
            "email": "admin@system.com",
            "password_hash": pwd_context.hash("admin123"),
            "name": "System Administrator",
            "role": "SUPERUSER",
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "email": "admin@tenant1.com",
            "password_hash": pwd_context.hash("admin123"),
            "name": "Luciana Admin",
            "role": "ADMIN",
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "email": "agent1@tenant1.com",
            "password_hash": pwd_context.hash("agent123"),
            "name": "Agent Rodriguez",
            "role": "AGENT",
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "email": "agent2@tenant1.com",
            "password_hash": pwd_context.hash("agent123"),
            "name": "Agent Martinez",
            "role": "AGENT",
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    ]
    
    await db.users.insert_many(users)
    
    # Create some demo leads
    print("Creating demo leads...")
    
    leads = [
        {
            "_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "external_lead_id": "LEAD_001",
            "source": "Luciana AI Chat",
            "customer": {
                "name": "Carlos Mendoza",
                "phone": "+34612345678",
                "email": "carlos@example.com"
            },
            "journey_stage": "qualified",
            "priority": "high",
            "status": "pending",
            "assigned_agent_id": None,
            "metadata": {
                "utm_source": "google",
                "utm_campaign": "ai_chat_2024",
                "interest": "chatbot_implementation"
            },
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "external_lead_id": "LEAD_002",
            "source": "Website Contact Form",
            "customer": {
                "name": "Maria Garcia",
                "phone": "+34687654321",
                "email": "maria@company.com"
            },
            "journey_stage": "inquiry",
            "priority": "medium",
            "status": "pending",
            "assigned_agent_id": None,
            "metadata": {
                "company": "Tech Innovations SL",
                "role": "CTO",
                "interest": "whatsapp_integration"
            },
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "external_lead_id": "LEAD_003",
            "source": "LinkedIn Campaign",
            "customer": {
                "name": "Roberto Silva",
                "phone": "+34611223344",
                "email": "r.silva@startup.com"
            },
            "journey_stage": "demo_requested",
            "priority": "high",
            "status": "pending",
            "assigned_agent_id": None,
            "metadata": {
                "company": "StartupTech",
                "employees": "50-100",
                "interest": "ai_customer_service"
            },
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    ]
    
    await db.leads.insert_many(leads)
    
    print("Demo data initialized successfully!")
    print("\nDemo Credentials:")
    print("SUPERUSER: admin@system.com / admin123")
    print("ADMIN: admin@tenant1.com / admin123")
    print("AGENT 1: agent1@tenant1.com / agent123")
    print("AGENT 2: agent2@tenant1.com / agent123")
    print(f"\nTenant ID: {tenant_id}")
    
    client.close()

if __name__ == "__main__":
    asyncio.run(init_demo_data())