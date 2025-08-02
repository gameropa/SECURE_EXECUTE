"""
Threat detection engine for identifying security vulnerabilities.
"""

import re
import html
from typing import List, Tuple, Any, Dict

class ThreatDetector:
    """Advanced threat detection for various security attacks."""
    
    def __init__(self):
        self.sql_patterns = [
            r"(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into)",
            r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*')",
            r"(?i)(exec\s*\(|execute\s*\(|sp_|xp_)",
            r"[\'\";].*[-]{2,}",  # SQL comments
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript\s*:",
            r"on\w+\s*=",  # onclick, onload etc.
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
        ]
        
        self.path_traversal_patterns = [
            r"\.\.[\\/]",
            r"\.\.%2f",
            r"\.\.%5c",
            r"%2e%2e[\\/]",
        ]
        
        self.code_injection_patterns = [
            r"(?i)\bexec\s*\(",
            r"(?i)\beval\s*\(",
            r"(?i)\bcompile\s*\(",
            r"(?i)__import__\s*\(",
            r"(?i)globals\s*\(\)",
            r"(?i)locals\s*\(\)",
        ]
        
        self.dos_patterns = [
            r"(.{1000,})",  # Very long strings
            r"(\w)\1{100,}",  # Repeated characters
        ]
    
    def detect_threats(self, data: Any, context: Dict = None) -> List[Tuple[str, str, str]]:
        """
        Detect all threats in given data.
        
        Args:
            data: Data to analyze
            context: Additional context information
            
        Returns:
            List of (threat_type, severity, description) tuples
        """
        threats = []
        
        # Convert data to string for analysis
        data_str = str(data) if data is not None else ""
        
        # SQL Injection Detection
        sql_threat = self._detect_sql_injection(data_str)
        if sql_threat:
            threats.append(sql_threat)
        
        # XSS Detection
        xss_threat = self._detect_xss(data_str)
        if xss_threat:
            threats.append(xss_threat)
        
        # Path Traversal Detection
        path_threat = self._detect_path_traversal(data_str)
        if path_threat:
            threats.append(path_threat)
        
        # Code Injection Detection
        code_threat = self._detect_code_injection(data_str)
        if code_threat:
            threats.append(code_threat)
        
        # DoS Detection
        dos_threat = self._detect_dos_patterns(data_str)
        if dos_threat:
            threats.append(dos_threat)
        
        return threats
    
    def _detect_code_injection(self, data: str) -> Tuple[str, str, str]:
        """Detect code injection attempts."""
        # Check code injection patterns first (higher priority)
        for pattern in self.code_injection_patterns:
            if re.search(pattern, data):
                return ("CODE_INJECTION", "CRITICAL", f"Code injection detected: {pattern}")
        return None
    
    def _detect_sql_injection(self, data: str) -> Tuple[str, str, str]:
        """Detect SQL injection patterns."""
        # Only check SQL patterns if it's not already detected as code injection
        for pattern in self.sql_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                # Additional check to avoid false positives with code injection
                if not any(re.search(code_pattern, data) for code_pattern in self.code_injection_patterns):
                    return ("SQL_INJECTION", "HIGH", f"SQL injection pattern detected: {pattern}")
        return None
    
    def _detect_xss(self, data: str) -> Tuple[str, str, str]:
        """Detect XSS attack patterns."""
        for pattern in self.xss_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return ("XSS", "MEDIUM", f"XSS pattern detected: {pattern}")
        return None
    
    def _detect_path_traversal(self, data: str) -> Tuple[str, str, str]:
        """Detect path traversal attempts."""
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return ("PATH_TRAVERSAL", "HIGH", f"Path traversal detected: {pattern}")
        return None
    
    def _detect_dos_patterns(self, data: str) -> Tuple[str, str, str]:
        """Detect potential DoS patterns."""
        if len(data) > 10000:  # Very large input
            return ("DOS", "MEDIUM", f"Oversized input detected: {len(data)} characters")
        
        for pattern in self.dos_patterns:
            if re.search(pattern, data):
                return ("DOS", "LOW", "Suspicious repetitive pattern detected")
        
        return None
        return None
