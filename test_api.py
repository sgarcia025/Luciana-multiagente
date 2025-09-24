#!/usr/bin/env python3
"""
Test script for WhatsApp CRM API
"""

import requests
import json

BASE_URL = "https://crmwarouter.preview.emergentagent.com/api"

def test_login():
    print("Testing login...")
    
    # Test admin login
    response = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "admin@tenant1.com",
        "password": "admin123"
    })
    
    if response.status_code == 200:
        data = response.json()
        print(f"✓ Login successful: {data['user']['name']} ({data['user']['role']})")
        return data['access_token']
    else:
        print(f"✗ Login failed: {response.status_code} - {response.text}")
        return None

def test_create_lead(token, tenant_id):
    print("\nTesting lead creation...")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-Id": tenant_id,
        "Content-Type": "application/json"
    }
    
    lead_data = {
        "external_lead_id": "LUCIANA_LEAD_001",
        "source": "Luciana AI Assistant",
        "customer": {
            "name": "Ana Jimenez",
            "phone": "+34600111222",
            "email": "ana@nuevaempresa.com"
        },
        "journey_stage": "initial_contact",
        "priority": "high",
        "metadata": {
            "conversation_id": "conv_12345",
            "bot_confidence": 0.95,
            "intent": "product_inquiry",
            "language": "es"
        },
        "callback_url": "https://luciana.ai/webhooks/crm-updates"
    }
    
    response = requests.post(f"{BASE_URL}/leads", json=lead_data, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print(f"✓ Lead created successfully: {data}")
        return data
    else:
        print(f"✗ Lead creation failed: {response.status_code} - {response.text}")
        return None

def test_agent_login_and_assignments():
    print("\nTesting agent login and assignments...")
    
    # Agent login
    response = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "agent1@tenant1.com",
        "password": "agent123"
    })
    
    if response.status_code != 200:
        print(f"✗ Agent login failed: {response.status_code}")
        return None
    
    agent_token = response.json()['access_token']
    agent_data = response.json()['user']
    print(f"✓ Agent login successful: {agent_data['name']}")
    
    # Get assignments
    headers = {"Authorization": f"Bearer {agent_token}"}
    response = requests.get(f"{BASE_URL}/assignments", headers=headers)
    
    if response.status_code == 200:
        assignments = response.json()
        print(f"✓ Found {len(assignments)} assignments")
        
        # Accept first pending assignment
        for assignment in assignments:
            if assignment['status'] == 'pending':
                accept_response = requests.post(
                    f"{BASE_URL}/assignments/{assignment['id']}/accept", 
                    headers=headers
                )
                if accept_response.status_code == 200:
                    print(f"✓ Assignment {assignment['id']} accepted successfully")
                    break
                else:
                    print(f"✗ Failed to accept assignment: {accept_response.text}")
        
        return agent_token
    else:
        print(f"✗ Failed to get assignments: {response.status_code}")
        return None

def main():
    print("WhatsApp CRM API Test Suite")
    print("=" * 40)
    
    # Test 1: Login
    token = test_login()
    if not token:
        return
    
    # Get tenant ID (hardcoded from init script)
    tenant_id = "9b342966-daf6-4962-b8d1-524aa0b0781f"
    
    # Test 2: Create lead
    lead_result = test_create_lead(token, tenant_id)
    
    # Test 3: Agent workflow
    agent_token = test_agent_login_and_assignments()
    
    print("\n" + "=" * 40)
    print("Test suite completed!")

if __name__ == "__main__":
    main()