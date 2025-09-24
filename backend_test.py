#!/usr/bin/env python3
"""
Comprehensive Backend API Test Suite for WhatsApp Multi-Agent Router CRM
"""

import requests
import sys
import json
from datetime import datetime

class WhatsAppCRMTester:
    def __init__(self, base_url="https://crmwarouter.preview.emergentagent.com/api"):
        self.base_url = base_url
        self.tokens = {}
        self.users = {}
        self.tenant_id = "9b342966-daf6-4962-b8d1-524aa0b0781f"
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            status = "✅ PASS"
        else:
            status = "❌ FAIL"
        
        result = f"{status} - {name}"
        if details:
            result += f" | {details}"
        
        print(result)
        self.test_results.append({
            "name": name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })
        return success

    def test_authentication(self):
        """Test authentication for all user roles"""
        print("\n🔐 Testing Authentication...")
        
        credentials = [
            ("SUPERUSER", "admin@system.com", "admin123"),
            ("ADMIN", "admin@tenant1.com", "admin123"),
            ("AGENT", "agent1@tenant1.com", "agent123")
        ]
        
        all_passed = True
        
        for role, email, password in credentials:
            try:
                response = requests.post(f"{self.base_url}/auth/login", json={
                    "email": email,
                    "password": password
                })
                
                if response.status_code == 200:
                    data = response.json()
                    self.tokens[role] = data['access_token']
                    self.users[role] = data['user']
                    success = self.log_test(f"Login {role}", True, f"User: {data['user']['name']}")
                else:
                    success = self.log_test(f"Login {role}", False, f"Status: {response.status_code}")
                    all_passed = False
                    
            except Exception as e:
                success = self.log_test(f"Login {role}", False, f"Error: {str(e)}")
                all_passed = False
        
        return all_passed

    def test_auth_me_endpoint(self):
        """Test /auth/me endpoint for each role"""
        print("\n👤 Testing /auth/me endpoint...")
        
        all_passed = True
        
        for role, token in self.tokens.items():
            try:
                headers = {"Authorization": f"Bearer {token}"}
                response = requests.get(f"{self.base_url}/auth/me", headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    expected_role = self.users[role]['role']
                    if data['role'] == expected_role:
                        success = self.log_test(f"Auth/me {role}", True, f"Role verified: {data['role']}")
                    else:
                        success = self.log_test(f"Auth/me {role}", False, f"Role mismatch: {data['role']} != {expected_role}")
                        all_passed = False
                else:
                    success = self.log_test(f"Auth/me {role}", False, f"Status: {response.status_code}")
                    all_passed = False
                    
            except Exception as e:
                success = self.log_test(f"Auth/me {role}", False, f"Error: {str(e)}")
                all_passed = False
        
        return all_passed

    def test_lead_creation(self):
        """Test lead creation with X-Tenant-Id header"""
        print("\n📋 Testing Lead Creation...")
        
        if "ADMIN" not in self.tokens:
            return self.log_test("Lead Creation", False, "No ADMIN token available")
        
        try:
            headers = {
                "Authorization": f"Bearer {self.tokens['ADMIN']}",
                "X-Tenant-Id": self.tenant_id,
                "Content-Type": "application/json"
            }
            
            lead_data = {
                "external_lead_id": f"TEST_LEAD_{datetime.now().strftime('%H%M%S')}",
                "source": "API Test Suite",
                "customer": {
                    "name": "Test Customer",
                    "phone": "+34600123456",
                    "email": "test@example.com"
                },
                "journey_stage": "test_stage",
                "priority": "medium",
                "metadata": {
                    "test": True,
                    "created_by": "backend_test"
                }
            }
            
            response = requests.post(f"{self.base_url}/leads", json=lead_data, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "router_lead_id" in data and "status" in data:
                    return self.log_test("Lead Creation", True, f"Lead ID: {data['router_lead_id']}")
                else:
                    return self.log_test("Lead Creation", False, "Missing required fields in response")
            else:
                return self.log_test("Lead Creation", False, f"Status: {response.status_code}, Response: {response.text}")
                
        except Exception as e:
            return self.log_test("Lead Creation", False, f"Error: {str(e)}")

    def test_lead_retrieval(self):
        """Test lead retrieval for different roles"""
        print("\n📊 Testing Lead Retrieval...")
        
        all_passed = True
        
        for role, token in self.tokens.items():
            try:
                headers = {"Authorization": f"Bearer {token}"}
                response = requests.get(f"{self.base_url}/leads", headers=headers)
                
                if response.status_code == 200:
                    leads = response.json()
                    success = self.log_test(f"Get Leads {role}", True, f"Found {len(leads)} leads")
                    if not success:
                        all_passed = False
                else:
                    success = self.log_test(f"Get Leads {role}", False, f"Status: {response.status_code}")
                    all_passed = False
                    
            except Exception as e:
                success = self.log_test(f"Get Leads {role}", False, f"Error: {str(e)}")
                all_passed = False
        
        return all_passed

    def test_assignments_retrieval(self):
        """Test assignments retrieval for different roles"""
        print("\n📝 Testing Assignments Retrieval...")
        
        all_passed = True
        
        for role, token in self.tokens.items():
            try:
                headers = {"Authorization": f"Bearer {token}"}
                response = requests.get(f"{self.base_url}/assignments", headers=headers)
                
                if response.status_code == 200:
                    assignments = response.json()
                    success = self.log_test(f"Get Assignments {role}", True, f"Found {len(assignments)} assignments")
                    if not success:
                        all_passed = False
                else:
                    success = self.log_test(f"Get Assignments {role}", False, f"Status: {response.status_code}")
                    all_passed = False
                    
            except Exception as e:
                success = self.log_test(f"Get Assignments {role}", False, f"Error: {str(e)}")
                all_passed = False
        
        return all_passed

    def test_users_endpoint(self):
        """Test users endpoint (Admin/Superuser only)"""
        print("\n👥 Testing Users Endpoint...")
        
        all_passed = True
        
        # Test authorized roles
        for role in ["SUPERUSER", "ADMIN"]:
            if role in self.tokens:
                try:
                    headers = {"Authorization": f"Bearer {self.tokens[role]}"}
                    response = requests.get(f"{self.base_url}/users", headers=headers)
                    
                    if response.status_code == 200:
                        users = response.json()
                        success = self.log_test(f"Get Users {role}", True, f"Found {len(users)} users")
                        if not success:
                            all_passed = False
                    else:
                        success = self.log_test(f"Get Users {role}", False, f"Status: {response.status_code}")
                        all_passed = False
                        
                except Exception as e:
                    success = self.log_test(f"Get Users {role}", False, f"Error: {str(e)}")
                    all_passed = False
        
        # Test unauthorized role (AGENT)
        if "AGENT" in self.tokens:
            try:
                headers = {"Authorization": f"Bearer {self.tokens['AGENT']}"}
                response = requests.get(f"{self.base_url}/users", headers=headers)
                
                if response.status_code == 403:
                    success = self.log_test("Get Users AGENT (should fail)", True, "Correctly denied access")
                else:
                    success = self.log_test("Get Users AGENT (should fail)", False, f"Expected 403, got {response.status_code}")
                    all_passed = False
                    
            except Exception as e:
                success = self.log_test("Get Users AGENT (should fail)", False, f"Error: {str(e)}")
                all_passed = False
        
        return all_passed

    def test_assignment_actions(self):
        """Test assignment accept/decline actions"""
        print("\n⚡ Testing Assignment Actions...")
        
        if "AGENT" not in self.tokens:
            return self.log_test("Assignment Actions", False, "No AGENT token available")
        
        try:
            # First get assignments for the agent
            headers = {"Authorization": f"Bearer {self.tokens['AGENT']}"}
            response = requests.get(f"{self.base_url}/assignments", headers=headers)
            
            if response.status_code != 200:
                return self.log_test("Assignment Actions", False, f"Failed to get assignments: {response.status_code}")
            
            assignments = response.json()
            pending_assignments = [a for a in assignments if a['status'] == 'pending']
            
            if not pending_assignments:
                return self.log_test("Assignment Actions", True, "No pending assignments to test (expected)")
            
            # Test accepting an assignment
            assignment_id = pending_assignments[0]['id']
            response = requests.post(f"{self.base_url}/assignments/{assignment_id}/accept", headers=headers)
            
            if response.status_code == 200:
                return self.log_test("Assignment Accept", True, f"Assignment {assignment_id} accepted")
            else:
                return self.log_test("Assignment Accept", False, f"Status: {response.status_code}, Response: {response.text}")
                
        except Exception as e:
            return self.log_test("Assignment Actions", False, f"Error: {str(e)}")

    def test_invalid_requests(self):
        """Test invalid requests and error handling"""
        print("\n🚫 Testing Error Handling...")
        
        all_passed = True
        
        # Test invalid login
        try:
            response = requests.post(f"{self.base_url}/auth/login", json={
                "email": "invalid@email.com",
                "password": "wrongpassword"
            })
            
            if response.status_code == 401:
                success = self.log_test("Invalid Login", True, "Correctly rejected invalid credentials")
            else:
                success = self.log_test("Invalid Login", False, f"Expected 401, got {response.status_code}")
                all_passed = False
                
        except Exception as e:
            success = self.log_test("Invalid Login", False, f"Error: {str(e)}")
            all_passed = False
        
        # Test lead creation without X-Tenant-Id
        if "ADMIN" in self.tokens:
            try:
                headers = {"Authorization": f"Bearer {self.tokens['ADMIN']}"}
                response = requests.post(f"{self.base_url}/leads", json={
                    "external_lead_id": "TEST_NO_TENANT",
                    "source": "Test",
                    "customer": {"name": "Test", "phone": "+123456789"}
                }, headers=headers)
                
                if response.status_code == 400:
                    success = self.log_test("Lead without Tenant-ID", True, "Correctly rejected request without X-Tenant-Id")
                else:
                    success = self.log_test("Lead without Tenant-ID", False, f"Expected 400, got {response.status_code}")
                    all_passed = False
                    
            except Exception as e:
                success = self.log_test("Lead without Tenant-ID", False, f"Error: {str(e)}")
                all_passed = False
        
        return all_passed

    def run_all_tests(self):
        """Run all test suites"""
        print("🚀 WhatsApp Multi-Agent Router CRM - Backend API Test Suite")
        print("=" * 70)
        
        test_suites = [
            ("Authentication", self.test_authentication),
            ("Auth Me Endpoint", self.test_auth_me_endpoint),
            ("Lead Creation", self.test_lead_creation),
            ("Lead Retrieval", self.test_lead_retrieval),
            ("Assignments Retrieval", self.test_assignments_retrieval),
            ("Users Endpoint", self.test_users_endpoint),
            ("Assignment Actions", self.test_assignment_actions),
            ("Error Handling", self.test_invalid_requests)
        ]
        
        suite_results = []
        
        for suite_name, test_func in test_suites:
            print(f"\n📋 Running {suite_name} Tests...")
            try:
                result = test_func()
                suite_results.append((suite_name, result))
            except Exception as e:
                print(f"❌ Test suite {suite_name} failed with error: {str(e)}")
                suite_results.append((suite_name, False))
        
        # Print summary
        print("\n" + "=" * 70)
        print("📊 TEST SUMMARY")
        print("=" * 70)
        
        for suite_name, result in suite_results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{status} - {suite_name}")
        
        print(f"\nOverall: {self.tests_passed}/{self.tests_run} tests passed")
        
        success_rate = (self.tests_passed / self.tests_run * 100) if self.tests_run > 0 else 0
        print(f"Success Rate: {success_rate:.1f}%")
        
        if success_rate >= 80:
            print("🎉 Backend API tests mostly successful!")
            return True
        else:
            print("⚠️  Backend API has significant issues that need attention")
            return False

def main():
    tester = WhatsAppCRMTester()
    success = tester.run_all_tests()
    
    # Save detailed results
    with open('/app/backend_test_results.json', 'w') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "total_tests": tester.tests_run,
            "passed_tests": tester.tests_passed,
            "success_rate": (tester.tests_passed / tester.tests_run * 100) if tester.tests_run > 0 else 0,
            "test_results": tester.test_results
        }, f, indent=2)
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())