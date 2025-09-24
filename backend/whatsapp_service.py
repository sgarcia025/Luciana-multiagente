"""
UltraMSG WhatsApp Integration Service
"""

import aiohttp
import json
from typing import Optional, Dict, Any
import os
from motor.motor_asyncio import AsyncIOMotorDatabase
import logging

logger = logging.getLogger(__name__)

class UltraMSGService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        
    async def get_tenant_config(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get WhatsApp configuration for a tenant"""
        tenant = await self.db.tenants.find_one({"_id": tenant_id})
        if tenant and tenant.get('wa_config'):
            wa_config = tenant['wa_config']
            if all([wa_config.get('api_base'), wa_config.get('api_key'), wa_config.get('phone_number')]):
                return wa_config
        return None
    
    async def send_text_message(self, tenant_id: str, to_phone: str, message: str) -> Dict[str, Any]:
        """Send text message via UltraMSG"""
        config = await self.get_tenant_config(tenant_id)
        if not config:
            return {"success": False, "error": "WhatsApp not configured for this tenant"}
        
        url = f"{config['api_base']}/messages/chat"
        
        data = {
            "token": config['api_key'],
            "to": to_phone,
            "body": message
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data) as response:
                    result = await response.json()
                    
                    if response.status == 200 and result.get('sent'):
                        return {
                            "success": True,
                            "message_id": result.get('id'),
                            "status": "sent"
                        }
                    else:
                        return {
                            "success": False,
                            "error": result.get('error', 'Unknown error'),
                            "details": result
                        }
        except Exception as e:
            logger.error(f"Error sending WhatsApp message: {e}")
            return {"success": False, "error": str(e)}
    
    async def send_image_message(self, tenant_id: str, to_phone: str, image_url: str, caption: str = "") -> Dict[str, Any]:
        """Send image message via UltraMSG"""
        config = await self.get_tenant_config(tenant_id)
        if not config:
            return {"success": False, "error": "WhatsApp not configured for this tenant"}
        
        url = f"{config['api_base']}/messages/image"
        
        data = {
            "token": config['api_key'],
            "to": to_phone,
            "image": image_url,
            "caption": caption
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data) as response:
                    result = await response.json()
                    
                    if response.status == 200 and result.get('sent'):
                        return {
                            "success": True,
                            "message_id": result.get('id'),
                            "status": "sent"
                        }
                    else:
                        return {
                            "success": False,
                            "error": result.get('error', 'Unknown error'),
                            "details": result
                        }
        except Exception as e:
            logger.error(f"Error sending WhatsApp image: {e}")
            return {"success": False, "error": str(e)}
    
    async def send_document_message(self, tenant_id: str, to_phone: str, document_url: str, filename: str = "") -> Dict[str, Any]:
        """Send document message via UltraMSG"""
        config = await self.get_tenant_config(tenant_id)
        if not config:
            return {"success": False, "error": "WhatsApp not configured for this tenant"}
        
        url = f"{config['api_base']}/messages/document"
        
        data = {
            "token": config['api_key'],
            "to": to_phone,
            "document": document_url,
            "filename": filename
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data) as response:
                    result = await response.json()
                    
                    if response.status == 200 and result.get('sent'):
                        return {
                            "success": True,
                            "message_id": result.get('id'),
                            "status": "sent"
                        }
                    else:
                        return {
                            "success": False,
                            "error": result.get('error', 'Unknown error'),
                            "details": result
                        }
        except Exception as e:
            logger.error(f"Error sending WhatsApp document: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_instance_status(self, tenant_id: str) -> Dict[str, Any]:
        """Check WhatsApp instance status"""
        config = await self.get_tenant_config(tenant_id)
        if not config:
            return {"success": False, "error": "WhatsApp not configured for this tenant"}
        
        url = f"{config['api_base']}/instance/status"
        
        try:
            async with aiohttp.ClientSession() as session:
                params = {"token": config['api_key']}
                async with session.get(url, params=params) as response:
                    result = await response.json()
                    
                    return {
                        "success": True,
                        "status": result.get('accountStatus'),
                        "phone": result.get('phoneNumber'),
                        "instance": result.get('instanceId')
                    }
        except Exception as e:
            logger.error(f"Error checking WhatsApp status: {e}")
            return {"success": False, "error": str(e)}

    def validate_webhook_signature(self, payload: str, signature: str, secret: str) -> bool:
        """Validate webhook signature from UltraMSG"""
        import hmac
        import hashlib
        
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)

    async def process_incoming_message(self, webhook_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process incoming WhatsApp message from webhook"""
        try:
            # Extract message data
            message_type = webhook_data.get('type', 'text')
            from_phone = webhook_data.get('from')
            message_id = webhook_data.get('id')
            timestamp = webhook_data.get('timestamp')
            
            # Find tenant by phone number
            phone_instance = webhook_data.get('instance')  # UltraMSG instance ID
            tenant = await self.db.tenants.find_one({
                "wa_config.phone_number": from_phone  # This needs to be instance-based
            })
            
            if not tenant:
                logger.warning(f"No tenant found for phone {from_phone}")
                return {"success": False, "error": "Tenant not found"}
            
            # Find or create conversation
            customer_phone = from_phone
            lead = await self.db.leads.find_one({
                "tenant_id": tenant["_id"],
                "customer.phone": customer_phone
            })
            
            if not lead:
                # Create new lead for incoming message
                from datetime import datetime, timezone
                import uuid
                
                lead_data = {
                    "_id": str(uuid.uuid4()),
                    "tenant_id": tenant["_id"],
                    "external_lead_id": f"WA_INCOMING_{message_id}",
                    "source": "WhatsApp Incoming",
                    "customer": {
                        "name": f"Customer {customer_phone}",
                        "phone": customer_phone,
                        "email": None
                    },
                    "journey_stage": "initial_contact",
                    "priority": "medium",
                    "status": "pending",
                    "assigned_agent_id": None,
                    "metadata": {
                        "channel": "whatsapp",
                        "first_message_id": message_id
                    },
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                
                await self.db.leads.insert_one(lead_data)
                lead = lead_data
            
            # Create message record
            message_data = {
                "_id": str(uuid.uuid4()),
                "tenant_id": tenant["_id"],
                "lead_id": lead["_id"],
                "whatsapp_message_id": message_id,
                "direction": "in",
                "type": message_type,
                "text": webhook_data.get('body', ''),
                "media_url": webhook_data.get('media_url'),
                "timestamp": timestamp,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            await self.db.messages.insert_one(message_data)
            
            return {
                "success": True,
                "lead_id": lead["_id"],
                "message_id": message_data["_id"]
            }
            
        except Exception as e:
            logger.error(f"Error processing incoming message: {e}")
            return {"success": False, "error": str(e)}