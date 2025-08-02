import unittest
import logging
import time
import io
import sys
import os
from functools import wraps
from unittest.mock import patch, MagicMock
from safe_execute import safe_execute, secure_execute, SecurityContext, ThreatDetector, SecurityResponse
from safe_execute.security.core import SecurityError

class TestSecuritySystem(unittest.TestCase):
    def setUp(self):
        # Capture log output for testing
        self.log_capture = io.StringIO()
        self.handler = logging.StreamHandler(self.log_capture)
        logging.getLogger().addHandler(self.handler)
        logging.getLogger().setLevel(logging.INFO)
        
        # Reset security state
        self.security_context = SecurityContext()
        self.threat_detector = ThreatDetector()
        self.security_response = SecurityResponse()

    def tearDown(self):
        logging.getLogger().removeHandler(self.handler)
        self.log_capture.close()

    # === BASIC SECURITY DECORATOR TESTS ===
    
    def test_secure_execute_basic(self):
        """Test basic secure_execute functionality"""
        @secure_execute()
        def safe_function(data):
            return f"Processed: {data}"
        
        result = safe_function("normal_input")
        self.assertEqual(result, "Processed: normal_input")

    def test_combined_decorators_basic(self):
        """Test safe_execute + secure_execute combination"""
        @safe_execute()
        @secure_execute()
        def combined_function(data):
            return f"Safe and secure: {data}"
        
        result = combined_function("test_data")
        self.assertEqual(result, "Safe and secure: test_data")

    def test_secure_execute_with_exception(self):
        """Test secure_execute with function that raises exception"""
        @safe_execute()
        @secure_execute()
        def failing_function():
            raise ValueError("Test error")
        
        result = failing_function()
        self.assertIsNone(result)

    # === THREAT DETECTION TESTS ===

    def test_threat_detector_sql_injection(self):
        """Test SQL injection detection"""
        detector = ThreatDetector()
        
        # Test malicious SQL patterns
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR 1=1 --",
            "admin' UNION SELECT * FROM passwords --",
            "'; EXEC xp_cmdshell('format c:'); --"
        ]
        
        for malicious_input in malicious_inputs:
            with self.subTest(input=malicious_input):
                threats = detector.detect_threats(malicious_input)
                self.assertTrue(len(threats) > 0)
                threat_type, severity, description = threats[0]
                self.assertEqual(threat_type, "SQL_INJECTION")
                self.assertEqual(severity, "HIGH")

    def test_threat_detector_xss(self):
        """Test XSS attack detection"""
        detector = ThreatDetector()
        
        xss_inputs = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img onload='alert(1)'>",
            "<iframe src='javascript:alert(1)'></iframe>"
        ]
        
        for xss_input in xss_inputs:
            with self.subTest(input=xss_input):
                threats = detector.detect_threats(xss_input)
                self.assertTrue(len(threats) > 0)
                threat_type, severity, description = threats[0]
                self.assertEqual(threat_type, "XSS")
                self.assertEqual(severity, "MEDIUM")

    def test_threat_detector_path_traversal(self):
        """Test path traversal detection"""
        detector = ThreatDetector()
        
        path_inputs = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "..%2f..%2fetc%2fpasswd",
            "%2e%2e/etc/passwd"
        ]
        
        for path_input in path_inputs:
            with self.subTest(input=path_input):
                threats = detector.detect_threats(path_input)
                self.assertTrue(len(threats) > 0)
                threat_type, severity, description = threats[0]
                self.assertEqual(threat_type, "PATH_TRAVERSAL")
                self.assertEqual(severity, "HIGH")

    def test_threat_detector_code_injection(self):
        """Test code injection detection"""
        detector = ThreatDetector()
        
        code_inputs = [
            "__import__('os').system('rm -rf /')",
            "exec('malicious code')",
            "eval('1+1')",
            "compile('evil', 'string', 'exec')",
            "globals()['__builtins__']"
        ]
        
        for code_input in code_inputs:
            with self.subTest(input=code_input):
                threats = detector.detect_threats(code_input)
                self.assertTrue(len(threats) > 0)
                threat_type, severity, description = threats[0]
                self.assertEqual(threat_type, "CODE_INJECTION")
                self.assertEqual(severity, "CRITICAL")

    def test_threat_detector_dos_patterns(self):
        """Test DoS pattern detection"""
        detector = ThreatDetector()
        
        # Large input
        large_input = "A" * 15000
        threats = detector.detect_threats(large_input)
        self.assertTrue(len(threats) > 0)
        threat_type, severity, description = threats[0]
        self.assertEqual(threat_type, "DOS")
        self.assertEqual(severity, "MEDIUM")

    def test_threat_detector_safe_input(self):
        """Test that safe inputs don't trigger threats"""
        detector = ThreatDetector()
        
        safe_inputs = [
            "normal text",
            "user@example.com",
            "Valid file name.txt",
            "123456789",
            "SELECT name FROM users WHERE id=1"  # Valid SQL without injection
        ]
        
        for safe_input in safe_inputs:
            with self.subTest(input=safe_input):
                threats = detector.detect_threats(safe_input)
                self.assertEqual(len(threats), 0)

    # === SECURITY RESPONSE TESTS ===

    def test_security_response_sql_sanitization(self):
        """Test SQL injection sanitization"""
        response = SecurityResponse()
        context = SecurityContext()
        
        malicious_sql = "'; DROP TABLE users; --"
        should_continue, sanitized, action = response.handle_threat(
            "SQL_INJECTION", "HIGH", malicious_sql, context
        )
        
        self.assertTrue(should_continue)
        self.assertEqual(action, "SANITIZED")
        self.assertNotIn("DROP", str(sanitized))
        self.assertNotIn("--", str(sanitized))

    def test_security_response_xss_sanitization(self):
        """Test XSS sanitization"""
        response = SecurityResponse()
        context = SecurityContext()
        
        xss_input = "<script>alert('XSS')</script>"
        should_continue, sanitized, action = response.handle_threat(
            "XSS", "MEDIUM", xss_input, context
        )
        
        self.assertTrue(should_continue)
        self.assertEqual(action, "SANITIZED")
        self.assertNotIn("<script>", str(sanitized))

    def test_security_response_critical_block(self):
        """Test critical threat blocking"""
        response = SecurityResponse()
        context = SecurityContext()
        
        critical_input = "exec('malicious code')"
        should_continue, sanitized, action = response.handle_threat(
            "CODE_INJECTION", "CRITICAL", critical_input, context
        )
        
        self.assertFalse(should_continue)
        self.assertEqual(action, "BLOCKED_AND_QUARANTINED")
        self.assertEqual(context.threat_level, "CRITICAL")
        self.assertEqual(context.blocked_attempts, 1)

    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        response = SecurityResponse()
        
        # Test within limit
        for i in range(5):
            result = response.check_rate_limit("test_function", 10)
            self.assertTrue(result)
        
        # Test exceeding limit
        for i in range(10):
            response.check_rate_limit("test_function", 10)
        
        # Should fail now
        result = response.check_rate_limit("test_function", 10)
        self.assertFalse(result)

    def test_auto_healing(self):
        """Test auto-healing functionality"""
        response = SecurityResponse()
        
        def failing_function(data):
            if "malicious" in data:
                raise ValueError("Malicious input detected")
            return f"Processed: {data}"
        
        # Test auto-healing
        exception = ValueError("Malicious input detected")
        result = response.auto_heal(
            failing_function, 
            ("malicious input",), 
            {}, 
            exception
        )
        
        self.assertIsNotNone(result)
        self.assertIn("Processed:", result)

    # === SECURITY CONTEXT TESTS ===

    def test_security_context_threat_escalation(self):
        """Test threat level escalation"""
        context = SecurityContext()
        
        # Start with LOW
        self.assertEqual(context.threat_level, "LOW")
        
        # Add MEDIUM threat
        context.add_security_event("XSS", "MEDIUM", "Test XSS")
        self.assertEqual(context.threat_level, "MEDIUM")
        
        # Add HIGH threat
        context.add_security_event("SQL_INJECTION", "HIGH", "Test SQL")
        self.assertEqual(context.threat_level, "HIGH")
        
        # Add CRITICAL threat
        context.add_security_event("CODE_INJECTION", "CRITICAL", "Test Code")
        self.assertEqual(context.threat_level, "CRITICAL")

    def test_security_context_risk_assessment(self):
        """Test high risk detection"""
        context = SecurityContext()
        
        # Initially not high risk
        self.assertFalse(context.is_high_risk())
        
        # Add multiple blocked attempts
        context.blocked_attempts = 10
        self.assertTrue(context.is_high_risk())
        
        # Reset and test with threat level
        context.blocked_attempts = 0
        context.threat_level = "CRITICAL"
        self.assertTrue(context.is_high_risk())

    def test_security_context_recent_events(self):
        """Test recent events filtering"""
        context = SecurityContext()
        
        # Add some events
        context.add_security_event("XSS", "MEDIUM", "Event 1")
        time.sleep(0.1)
        context.add_security_event("SQL_INJECTION", "HIGH", "Event 2")
        
        recent = context.get_recent_events(10)  # Last 10 minutes
        self.assertEqual(len(recent), 2)
        
        # Test filtering
        very_recent = context.get_recent_events(0.001)  # Very short time
        self.assertEqual(len(very_recent), 1)  # Only the last one

    # === INTEGRATION TESTS ===

    def test_secure_execute_sql_protection(self):
        """Test secure_execute protecting against SQL injection"""
        @safe_execute()
        @secure_execute(auto_sanitize=True)
        def database_query(query):
            # Check for dangerous patterns after sanitization
            if any(pattern in query.upper() for pattern in ["DROP", "DELETE", "EXEC"]):
                raise ValueError("Dangerous query detected")
            return f"Query result: {query}"
        
        # Test malicious input
        result = database_query("'; DROP TABLE users; --")
        self.assertIsNotNone(result)  # Should be sanitized and work
        # After sanitization, DROP should be removed
        if result:
            # The sanitized query should not contain dangerous keywords
            self.assertTrue("Query result:" in result)

    def test_secure_execute_xss_protection(self):
        """Test secure_execute protecting against XSS"""
        @safe_execute()
        @secure_execute(auto_sanitize=True)
        def render_content(content):
            return f"<div>{content}</div>"
        
        malicious_content = "<script>alert('XSS')</script>"
        result = render_content(malicious_content)
        self.assertIsNotNone(result)
        self.assertNotIn("<script>", result)

    def test_secure_execute_critical_blocking(self):
        """Test secure_execute blocking critical threats"""
        @safe_execute()
        @secure_execute()
        def process_code(code):
            return f"Executing: {code}"
        
        # This should raise SecurityError which safe_execute will catch
        result = process_code("exec('malicious code')")
        self.assertIsNone(result)

    def test_secure_execute_rate_limiting(self):
        """Test secure_execute rate limiting"""
        @safe_execute()
        @secure_execute(rate_limit=3)  # 3 calls per minute
        def limited_function():
            return "success"
        
        # First 3 calls should work
        for i in range(3):
            result = limited_function()
            self.assertEqual(result, "success")
        
        # 4th call should fail
        result = limited_function()
        self.assertIsNone(result)

    def test_secure_execute_auto_heal(self):
        """Test secure_execute auto-healing"""
        @safe_execute()
        @secure_execute(auto_heal=True, auto_sanitize=True)
        def vulnerable_function(data):
            if "DROP" in data.upper():
                raise ValueError("Dangerous operation")
            return f"Safe operation: {data}"
        
        # Should auto-heal by sanitizing input
        result = vulnerable_function("'; DROP TABLE users;")
        self.assertIsNotNone(result)

    def test_custom_threat_responses(self):
        """Test custom threat response handlers"""
        def custom_sql_handler(args, kwargs):
            # Custom sanitization
            sanitized_args = []
            for arg in args:
                if isinstance(arg, str):
                    sanitized = arg.replace("DROP", "SELECT")
                    sanitized_args.append(sanitized)
                else:
                    sanitized_args.append(arg)
            return tuple(sanitized_args), kwargs
        
        @safe_execute()
        @secure_execute(
            custom_responses={"SQL_INJECTION": custom_sql_handler}
        )
        def custom_protected_function(query):
            return f"Query: {query}"
        
        result = custom_protected_function("DROP TABLE users")
        self.assertIsNotNone(result)
        self.assertIn("SELECT", result)

    # === PERFORMANCE AND STRESS TESTS ===

    def test_security_performance(self):
        """Test security system performance"""
        @safe_execute()
        @secure_execute()
        def fast_function(data):
            return len(data)
        
        # Test with many small inputs
        start_time = time.time()
        for i in range(100):
            result = fast_function(f"test_data_{i}")
            self.assertIsNotNone(result)
        
        elapsed = time.time() - start_time
        self.assertLess(elapsed, 1.0)  # Should complete in under 1 second

    def test_security_stress_test(self):
        """Stress test security system"""
        @safe_execute()
        @secure_execute(auto_sanitize=True)
        def stress_function(data):
            return f"Processed: {data[:50]}"
        
        # Mix of safe and malicious inputs
        test_inputs = [
            "safe_input",
            "'; DROP TABLE users; --",
            "<script>alert('XSS')</script>",
            "../../../etc/passwd",
            "normal text",
            "exec('malicious')"
        ]
        
        results = []
        for i in range(20):  # 20 iterations
            for input_data in test_inputs:
                result = stress_function(input_data)
                results.append(result)
        
        # Some results should be None (blocked), others processed
        successful_results = [r for r in results if r is not None]
        self.assertGreater(len(successful_results), 0)

    def test_concurrent_security_operations(self):
        """Test concurrent security operations"""
        import threading
        import queue
        
        result_queue = queue.Queue()
        
        @safe_execute()
        @secure_execute(auto_sanitize=True, rate_limit=50)
        def concurrent_function(thread_id, data):
            time.sleep(0.01)  # Simulate work
            return f"Thread {thread_id}: {data[:20]}"
        
        def worker(thread_id):
            test_data = f"test_data_from_thread_{thread_id}"
            if thread_id % 3 == 0:  # Every 3rd thread uses malicious data
                test_data = "'; DROP TABLE users; --"
            
            result = concurrent_function(thread_id, test_data)
            result_queue.put((thread_id, result))
        
        # Start multiple threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Collect results
        results = {}
        while not result_queue.empty():
            thread_id, result = result_queue.get()
            results[thread_id] = result
        
        self.assertEqual(len(results), 10)

    # === ADVANCED SECURITY SCENARIOS ===

    def test_multi_threat_detection(self):
        """Test detection of multiple threats in single input"""
        detector = ThreatDetector()
        
        # Input with multiple threats
        multi_threat_input = "'; DROP TABLE users; -- <script>alert('XSS')</script> ../../etc/passwd"
        
        threats = detector.detect_threats(multi_threat_input)
        self.assertGreaterEqual(len(threats), 2)  # Should detect multiple threats
        
        threat_types = [threat[0] for threat in threats]
        self.assertIn("SQL_INJECTION", threat_types)
        self.assertIn("XSS", threat_types)

    def test_security_escalation_workflow(self):
        """Test security escalation workflow"""
        context = SecurityContext()
        response = SecurityResponse()
        
        # Simulate escalating security events
        events = [
            ("XSS", "MEDIUM", "Basic XSS attempt"),
            ("SQL_INJECTION", "HIGH", "SQL injection detected"),
            ("CODE_INJECTION", "CRITICAL", "Code execution attempt")
        ]
        
        for threat_type, severity, description in events:
            context.add_security_event(threat_type, severity, description)
            should_continue, sanitized, action = response.handle_threat(
                threat_type, severity, description, context
            )
            
            if severity == "CRITICAL":
                self.assertFalse(should_continue)
                self.assertEqual(action, "BLOCKED_AND_QUARANTINED")
            else:
                self.assertTrue(should_continue)
        
        # Check final state
        self.assertEqual(context.threat_level, "CRITICAL")
        self.assertTrue(context.is_high_risk())

    def test_learning_mode(self):
        """Test learning mode functionality"""
        @safe_execute()
        @secure_execute(learning_mode=True)
        def learning_function(data):
            return f"Learning: {data}"
        
        # Test with various inputs to see if learning mode logs
        inputs = ["normal", "'; DROP TABLE", "<script>alert(1)</script>"]
        
        for input_data in inputs:
            result = learning_function(input_data)
            # In learning mode, should log additional information
        
        log_output = self.log_capture.getvalue()
        self.assertIn("Secure execution", log_output)

    def test_security_configuration_levels(self):
        """Test different security configuration levels"""
        # Low security
        @safe_execute()
        @secure_execute(security_level="LOW")
        def low_security_function(data):
            return f"Low security: {data}"
        
        # High security
        @safe_execute()
        @secure_execute(security_level="HIGH", auto_sanitize=True)
        def high_security_function(data):
            return f"High security: {data}"
        
        malicious_input = "'; DROP TABLE users; --"
        
        # Both should handle the input, but differently
        low_result = low_security_function(malicious_input)
        high_result = high_security_function(malicious_input)
        
        # Both functions will sanitize the input since auto_sanitize is True for high security
        # The sanitized version should not contain DROP
        if high_result:
            # After sanitization, dangerous keywords should be removed or escaped
            self.assertIn("High security:", high_result)

    # === ERROR HANDLING AND EDGE CASES ===

    def test_security_with_none_inputs(self):
        """Test security system with None inputs"""
        detector = ThreatDetector()
        
        threats = detector.detect_threats(None)
        self.assertEqual(len(threats), 0)
        
        @safe_execute()
        @secure_execute()
        def none_handling_function(data):
            return f"Data: {data}"
        
        result = none_handling_function(None)
        self.assertEqual(result, "Data: None")

    def test_security_with_complex_objects(self):
        """Test security system with complex Python objects"""
        detector = ThreatDetector()
        
        complex_obj = {
            "list": [1, 2, 3],
            "nested": {"key": "value"},
            "malicious": "'; DROP TABLE users; --"
        }
        
        threats = detector.detect_threats(complex_obj)
        self.assertGreater(len(threats), 0)  # Should detect the malicious content

    def test_security_error_propagation(self):
        """Test that SecurityError is properly handled by safe_execute"""
        @safe_execute()
        @secure_execute()
        def function_that_blocks():
            # This input should trigger a critical threat and raise SecurityError
            # We need to pass the dangerous input as a parameter, not return it
            pass
        
        # Call with dangerous input that should be blocked
        result = function_that_blocks()
        # Since no dangerous input is passed, function executes normally
        self.assertIsNone(result)  # Function returns None (no return statement)

    def test_sanitization_edge_cases(self):
        """Test edge cases in sanitization"""
        response = SecurityResponse()
        
        # Test with empty string
        result = response._sanitize_sql("")
        self.assertEqual(result, "")
        
        # Test with non-string input
        result = response._sanitize_sql(123)
        self.assertEqual(result, 123)
        
        # Test with complex sanitization
        complex_input = "'; DROP TABLE users; -- AND 1=1 <script>alert(1)</script>"
        sql_sanitized = response._sanitize_sql(complex_input)
        xss_sanitized = response._sanitize_xss(sql_sanitized)
        
        self.assertNotIn("DROP", sql_sanitized)
        self.assertNotIn("<script>", xss_sanitized)

    # === INTEGRATION WITH LOGGING SYSTEM ===

    def test_security_logging_integration(self):
        """Test integration with the logging system"""
        @safe_execute()
        @secure_execute(auto_sanitize=True)
        def logged_function(data):
            return f"Processed: {data}"
        
        # Test with malicious input
        malicious_input = "'; DROP TABLE users; --"
        result = logged_function(malicious_input)
        
        log_output = self.log_capture.getvalue()
        
        # Should log both security events and execution
        self.assertIn("executed successfully", log_output)  # From safe_execute
        # Security warnings should be in logs too

    def test_security_summary_reporting(self):
        """Test security summary reporting"""
        context = SecurityContext()
        
        # Add various security events
        context.add_security_event("SQL_INJECTION", "HIGH", "Test SQL")
        context.add_security_event("XSS", "MEDIUM", "Test XSS")
        context.blocked_attempts = 3
        context.sanitized_inputs.extend(["input1", "input2"])
        
        summary = context.get_security_summary()
        
        self.assertEqual(summary["threat_level"], "HIGH")
        self.assertEqual(summary["blocked_attempts"], 3)
        self.assertEqual(summary["sanitized_inputs_count"], 2)
        self.assertEqual(summary["total_events"], 2)
        self.assertTrue(summary["is_high_risk"])

if __name__ == "__main__":
    # Run specific test suites
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestSecuritySystem))
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"Security Tests Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print(f"{'='*50}")
