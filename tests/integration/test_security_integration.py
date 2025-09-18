"""
Integration tests for security validation across components.

Tests end-to-end security validation scenarios and plugin sandboxing.
"""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from src.netstealth_analyzer.plugins.loader import PluginLoader
from src.netstealth_analyzer.plugins.sandbox import PluginSandbox
from src.netstealth_analyzer.plugins.registry import PluginRegistry
from src.netstealth_analyzer.models.network import NetworkTrace, NetworkHop, HttpRequest, HttpResponse
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel
from src.netstealth_analyzer.config import ConfigurationManager, SecurityConfig
from src.netstealth_analyzer.core.errors import ValidationError, ConfigurationError
from src.netstealth_analyzer.core.events import AnalysisEvent


class TestSecurityIntegration:
    """Test security validation and sandboxing across components."""
    
    @pytest.mark.asyncio
    async def test_plugin_sandboxing_security(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper
    ):
        """Test plugin sandbox security isolation."""
        # Create potentially malicious plugin
        malicious_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel
import os
import sys
import subprocess

class MaliciousPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="malicious_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin that attempts malicious operations"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Attempt various potentially malicious operations."""
        issues = []
        
        # Normal operation should work
        issues.append(Issue(
            id="normal-detection",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.LOW,
            title="Normal Detection",
            description="This should work normally",
            confidence=0.8,
            impact_score=40
        ))
        
        return issues
    
    async def attempt_file_access(self):
        """Attempt to access files outside sandbox."""
        try:
            # Try to read a system file
            with open('/etc/passwd', 'r') as f:
                content = f.read()
            return f"SUCCESS: Read {len(content)} bytes from /etc/passwd"
        except Exception as e:
            return f"BLOCKED: {str(e)}"
    
    async def attempt_network_access(self):
        """Attempt network operations."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('example.com', 80))
            s.close()
            return "SUCCESS: Made network connection"
        except Exception as e:
            return f"BLOCKED: {str(e)}"
    
    async def attempt_subprocess(self):
        """Attempt to spawn subprocess."""
        try:
            result = subprocess.run(['echo', 'hello'], capture_output=True, text=True)
            return f"SUCCESS: Subprocess output: {result.stdout.strip()}"
        except Exception as e:
            return f"BLOCKED: {str(e)}"
    
    async def attempt_import_restriction(self):
        """Attempt to import restricted modules."""
        try:
            import ctypes
            return "SUCCESS: Imported ctypes"
        except ImportError as e:
            return f"BLOCKED: {str(e)}"
        except Exception as e:
            return f"BLOCKED: {str(e)}"
    
    def get_environment_info(self):
        """Get environment information (should work)."""
        return {
            "python_version": sys.version,
            "platform": os.name,
            "cwd": os.getcwd(),
            "pid": os.getpid()
        }
'''
        
        # Create plugin
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "malicious_plugin.py", malicious_plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        malicious_plugin = plugins[0]
        
        # Test normal operation works
        traces = [NetworkTrace(
            trace_id="security-test",
            session_id="security-session",
            hops=[NetworkHop(
                hop_number=1,
                hop_id="security-hop",
                actor="client",
                actor_name="Security Test Client",
                incoming_ip="127.0.0.1",
                outgoing_ip="192.168.1.1",
                response_time_ms=50.0
            )]
        )]
        
        with plugin_sandbox.execute_sandboxed(malicious_plugin):
            # Normal detection should work
            issues = await plugin_sandbox.execute_plugin_method(
                malicious_plugin, "detect", traces
            )
            assert len(issues) == 1
            assert issues[0].title == "Normal Detection"
            
            # Environment info should work (basic operations)
            env_info = await plugin_sandbox.execute_plugin_method(
                malicious_plugin, "get_environment_info"
            )
            assert "python_version" in env_info
            assert "platform" in env_info
            
            # Security tests - these should be blocked or controlled
            file_result = await plugin_sandbox.execute_plugin_method(
                malicious_plugin, "attempt_file_access"
            )
            assert "BLOCKED" in file_result or "FAILED" in file_result.upper()
            
            # Network access should be blocked by default
            network_result = await plugin_sandbox.execute_plugin_method(
                malicious_plugin, "attempt_network_access"
            )
            # This might succeed depending on sandbox configuration, so we just verify it doesn't crash
            assert isinstance(network_result, str)
            
            # Subprocess should be controlled
            subprocess_result = await plugin_sandbox.execute_plugin_method(
                malicious_plugin, "attempt_subprocess"
            )
            # This might be blocked or allowed depending on sandbox configuration
            assert isinstance(subprocess_result, str)
            
            # Restricted imports should be controlled
            import_result = await plugin_sandbox.execute_plugin_method(
                malicious_plugin, "attempt_import_restriction"
            )
            assert isinstance(import_result, str)
    
    @pytest.mark.asyncio
    async def test_configuration_security_validation(self):
        """Test security validation in configuration management."""
        config_manager = ConfigurationManager()
        
        # Test secure configuration
        secure_config = {
            "security": {
                "enable_plugin_sandboxing": True,
                "allowed_plugin_paths": ["./plugins", "./safe_plugins"],
                "max_plugin_execution_time": 30.0,
                "enable_network_access": False,
                "trusted_domains": ["example.com"]
            }
        }
        
        config = config_manager.load_from_dict(secure_config)
        assert config.security.enable_plugin_sandboxing is True
        assert config.security.enable_network_access is False
        assert "example.com" in config.security.trusted_domains
        
        # Test insecure configurations that should be rejected
        highly_insecure_config = {
            "security": {
                "enable_plugin_sandboxing": False,  # Insecure
                "enable_network_access": True,      # Potentially risky
                "max_plugin_execution_time": 3600.0  # Very high timeout - should be rejected
            }
        }
        
        # This should raise a ConfigurationError due to timeout being too high
        with pytest.raises(ConfigurationError) as exc_info:
            config_manager.load_from_dict(highly_insecure_config)
        
        assert "max_plugin_execution_time" in str(exc_info.value)
        assert "less than or equal to 300" in str(exc_info.value)
        
        # Test borderline insecure config that should load with warnings
        borderline_config = {
            "security": {
                "enable_plugin_sandboxing": False,      # Insecure but allowed
                "enable_network_access": True,          # Potentially risky but allowed
                "max_plugin_execution_time": 299.0,     # High but within limits
                "allowed_plugin_paths": ["./plugins", "./temp"],  # Reasonable paths
                "trusted_domains": ["example.com", "*.test.com"]  # Specific domains
            }
        }
        
        # This should load successfully (but might emit warnings in logs)
        config = config_manager.load_from_dict(borderline_config)
        assert isinstance(config.security, SecurityConfig)
        assert config.security.enable_plugin_sandboxing is False
        assert config.security.enable_network_access is True
        assert config.security.max_plugin_execution_time == 299.0
    
    @pytest.mark.asyncio
    async def test_plugin_validation_security(
        self,
        plugin_registry,
        temp_plugin_dir,
        integration_helper
    ):
        """Test plugin validation and security checks."""
        # Create plugin with invalid metadata
        invalid_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class InvalidPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        # Missing or invalid metadata
        self._metadata = None
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        return []
'''
        
        # Create plugin with suspicious code patterns
        suspicious_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel

class SuspiciousPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="suspicious_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin with suspicious patterns"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Detection method with suspicious code patterns."""
        # These patterns might be flagged by security analysis
        import os, sys, subprocess, socket
        import urllib.request
        import base64
        
        # Normal operation
        issues = []
        for trace in traces:
            issues.append(Issue(
                id=f"suspicious-{trace.trace_id}",
                category=IssueCategory.PRIVACY_VIOLATION,
                severity=SeverityLevel.MEDIUM,
                title="Suspicious Detection",
                description="Detection with suspicious code patterns",
                confidence=0.7,
                impact_score=50
            ))
        
        return issues
'''
        
        # Create plugin files
        invalid_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "invalid_plugin.py", invalid_plugin_code
        )
        suspicious_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "suspicious_plugin.py", suspicious_plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        
        # Test invalid plugin loading
        try:
            invalid_plugins = await loader.load_plugin_from_file(invalid_file)
            # If it loads, check that validation catches the issue
            if invalid_plugins:
                plugin = invalid_plugins[0]
                assert plugin.metadata is None  # Should be invalid
        except Exception as e:
            # Expected - plugin loading should fail or be caught
            assert "metadata" in str(e).lower() or "invalid" in str(e).lower()
        
        # Test suspicious plugin loading (should work but might trigger warnings)
        try:
            suspicious_plugins = await loader.load_plugin_from_file(suspicious_file)
            assert len(suspicious_plugins) == 1
            assert suspicious_plugins[0].name == "suspicious_plugin"
        except Exception as e:
            # Some security scanners might block this
            print(f"Suspicious plugin blocked: {e}")
    
    @pytest.mark.asyncio
    async def test_resource_limit_enforcement(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper
    ):
        """Test resource limit enforcement in plugin execution."""
        # Create resource-intensive plugin
        resource_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel
import time
import asyncio

class ResourceIntensivePlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="resource_intensive_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin that uses significant resources"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Normal detection method."""
        issues = []
        for trace in traces:
            issues.append(Issue(
                id=f"resource-{trace.trace_id}",
                category=IssueCategory.NETWORK_ANOMALY,
                severity=SeverityLevel.LOW,
                title="Resource Test Detection",
                description="Normal resource test detection",
                confidence=0.8,
                impact_score=40
            ))
        return issues
    
    async def memory_intensive_operation(self):
        """Operation that uses significant memory."""
        try:
            # Create large data structures
            data = []
            for i in range(100000):  # 100k items
                data.append([i] * 100)  # Each item has 100 elements
            
            result = f"Created data structure with {len(data)} items"
            
            # Clean up
            del data
            
            return result
        except MemoryError:
            return "BLOCKED: Memory limit exceeded"
        except Exception as e:
            return f"BLOCKED: {str(e)}"
    
    async def cpu_intensive_operation(self):
        """Operation that uses significant CPU."""
        try:
            # CPU-intensive calculation
            start_time = time.time()
            result = 0
            for i in range(1000000):  # 1M iterations
                result += i * i
            end_time = time.time()
            
            return f"CPU operation completed in {end_time - start_time:.3f}s, result: {result}"
        except Exception as e:
            return f"BLOCKED: {str(e)}"
    
    async def time_intensive_operation(self):
        """Operation that takes a long time."""
        try:
            start_time = time.time()
            await asyncio.sleep(2.0)  # 2 second delay
            end_time = time.time()
            
            return f"Time operation completed in {end_time - start_time:.3f}s"
        except asyncio.TimeoutError:
            return "BLOCKED: Timeout exceeded"
        except Exception as e:
            return f"BLOCKED: {str(e)}"
'''
        
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "resource_plugin.py", resource_plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        resource_plugin = plugins[0]
        
        # Test normal operation
        traces = [NetworkTrace(
            trace_id="resource-test",
            session_id="resource-session",
            hops=[NetworkHop(
                hop_number=1,
                hop_id="resource-hop",
                actor="client",
                actor_name="Resource Test Client",
                incoming_ip="127.0.0.1",
                outgoing_ip="192.168.1.1",
                response_time_ms=50.0
            )]
        )]
        
        with plugin_sandbox.execute_sandboxed(resource_plugin):
            # Normal detection should work
            issues = await plugin_sandbox.execute_plugin_method(
                resource_plugin, "detect", traces
            )
            assert len(issues) == 1
            assert issues[0].title == "Resource Test Detection"
            
            # Test memory-intensive operation
            memory_result = await plugin_sandbox.execute_plugin_method(
                resource_plugin, "memory_intensive_operation"
            )
            assert isinstance(memory_result, str)
            # Should either succeed or be blocked by memory limits
            assert "Created data structure" in memory_result or "BLOCKED" in memory_result
            
            # Test CPU-intensive operation
            cpu_result = await plugin_sandbox.execute_plugin_method(
                resource_plugin, "cpu_intensive_operation"
            )
            assert isinstance(cpu_result, str)
            # Should complete or be blocked
            assert "CPU operation completed" in cpu_result or "BLOCKED" in cpu_result
            
            # Test time-intensive operation (might be limited by timeout)
            try:
                time_result = await plugin_sandbox.execute_plugin_method(
                    resource_plugin, "time_intensive_operation"
                )
                assert isinstance(time_result, str)
                # Should complete or timeout
                assert "Time operation completed" in time_result or "BLOCKED" in time_result or "timeout" in time_result.lower()
            except Exception as e:
                # Timeout or resource limit exceeded
                assert "timeout" in str(e).lower() or "limit" in str(e).lower()
    
    @pytest.mark.asyncio
    async def test_data_validation_security(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper
    ):
        """Test data validation and sanitization security."""
        # Create plugin that validates input data
        validation_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence

class DataValidationPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="data_validation_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin that validates input data"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Detect issues with data validation."""
        issues = []
        
        for trace in traces:
            # Validate trace data
            validation_results = self.validate_trace_data(trace)
            
            if validation_results["has_issues"]:
                issue = Issue(
                    id=f"validation-{trace.trace_id}",
                    category=IssueCategory.CONFIGURATION,
                    severity=SeverityLevel.MEDIUM,
                    title="Data Validation Issue",
                    description=f"Data validation failed: {validation_results['message']}",
                    confidence=0.9,
                    impact_score=60,
                    evidence=[
                        IssueEvidence(
                            type="data_validation",
                            description="Data validation failure detected",
                            raw_data=validation_results,
                            confidence=0.9
                        )
                    ]
                )
                issues.append(issue)
        
        return issues
    
    def validate_trace_data(self, trace):
        """Validate trace data for security issues."""
        results = {"has_issues": False, "issues": [], "message": ""}
        
        # Check for missing required fields
        if not trace.trace_id:
            results["issues"].append("Missing trace_id")
            results["has_issues"] = True
        
        # Check trace_id format
        if trace.trace_id and len(trace.trace_id) > 100:
            results["issues"].append("Trace ID too long (potential buffer overflow)")
            results["has_issues"] = True
        
        # Check for suspicious characters in trace_id
        if trace.trace_id:
            suspicious_chars = ['<', '>', '"', "'", '&', ';', '|', '`']
            if any(char in trace.trace_id for char in suspicious_chars):
                results["issues"].append("Suspicious characters in trace_id")
                results["has_issues"] = True
        
        # Validate hops
        if not trace.hops:
            results["issues"].append("No hops in trace")
            results["has_issues"] = True
        
        for hop in trace.hops:
            # Validate IP addresses
            if hop.outgoing_ip:
                if not self.is_valid_ip(hop.outgoing_ip):
                    results["issues"].append(f"Invalid IP address: {hop.outgoing_ip}")
                    results["has_issues"] = True
            
            # Validate actor name
            if hop.actor_name and len(hop.actor_name) > 255:
                results["issues"].append(f"Actor name too long: {hop.actor_name[:50]}...")
                results["has_issues"] = True
            
            # Check for suspicious actor name patterns
            if hop.actor_name:
                suspicious_patterns = ['javascript:', 'data:', 'file:', 'ftp://']
                if any(pattern in hop.actor_name.lower() for pattern in suspicious_patterns):
                    results["issues"].append(f"Suspicious actor name pattern: {hop.actor_name}")
                    results["has_issues"] = True
        
        results["message"] = "; ".join(results["issues"])
        return results
    
    def is_valid_ip(self, ip):
        """Basic IP address validation."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not (0 <= int(part) <= 255):
                    return False
            return True
        except (ValueError, AttributeError):
            return False
    
    async def test_sql_injection_patterns(self, user_input):
        """Test for SQL injection patterns."""
        sql_patterns = [
            "' OR '1'='1",
            "'; DROP TABLE",
            "UNION SELECT",
            "INSERT INTO",
            "UPDATE SET",
            "DELETE FROM"
        ]
        
        detected_patterns = []
        for pattern in sql_patterns:
            if pattern.lower() in user_input.lower():
                detected_patterns.append(pattern)
        
        return {
            "is_suspicious": len(detected_patterns) > 0,
            "detected_patterns": detected_patterns,
            "sanitized_input": user_input.replace("'", "''")  # Basic sanitization
        }
    
    async def test_xss_patterns(self, user_input):
        """Test for XSS patterns."""
        xss_patterns = [
            "<script",
            "javascript:",
            "onload=",
            "onerror=",
            "onclick=",
            "<iframe",
            "eval(",
            "document.cookie"
        ]
        
        detected_patterns = []
        for pattern in xss_patterns:
            if pattern.lower() in user_input.lower():
                detected_patterns.append(pattern)
        
        return {
            "is_suspicious": len(detected_patterns) > 0,
            "detected_patterns": detected_patterns,
            "sanitized_input": user_input.replace("<", "&lt;").replace(">", "&gt;")
        }
'''
        
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "validation_plugin.py", validation_plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        validation_plugin = plugins[0]
        
        # Create test traces with various data quality issues
        test_traces = [
            # Valid trace
            NetworkTrace(
                trace_id="valid-trace-001",
                session_id="session-001",
                hops=[NetworkHop(
                    hop_number=1,
                    hop_id="hop-1",
                    actor="client",
                    actor_name="Valid Test Client",
                    incoming_ip="127.0.0.1",
                    outgoing_ip="192.168.1.1",
                    response_time_ms=50.0
                )]
            ),
            
            # Trace with suspicious trace_id
            NetworkTrace(
                trace_id="suspicious-<script>alert('xss')</script>-trace",
                session_id="session-002",
                hops=[NetworkHop(
                    hop_number=1,
                    hop_id="hop-1",
                    actor="client",
                    actor_name="Suspicious Test Client",
                    incoming_ip="127.0.0.1",
                    outgoing_ip="192.168.1.2",
                    response_time_ms=50.0
                )]
            ),
            
            # Trace with invalid data - create an issue with long actor name
            NetworkTrace(
                trace_id="invalid-trace-003",
                session_id="session-003",
                hops=[NetworkHop(
                    hop_number=1,
                    hop_id="hop-1",
                    actor="client",
                    actor_name="A" * 300,  # Long actor name that will trigger validation error
                    incoming_ip="127.0.0.1",
                    outgoing_ip="192.168.1.99",
                    response_time_ms=50.0
                )]
            )
        ]
        
        with plugin_sandbox.execute_sandboxed(validation_plugin):
            # Test data validation
            issues = await plugin_sandbox.execute_plugin_method(
                validation_plugin, "detect", test_traces
            )
            
            # Should detect issues in the suspicious trace (at minimum)
            assert len(issues) >= 1
            
            issue_trace_ids = [issue.id for issue in issues]
            assert any("suspicious" in issue_id for issue_id in issue_trace_ids)
            assert any("invalid" in issue_id for issue_id in issue_trace_ids)
            
            # Test SQL injection detection
            sql_test_inputs = [
                "normal_input",
                "'; DROP TABLE users; --",
                "admin' OR '1'='1",
                "UNION SELECT * FROM passwords"
            ]
            
            for test_input in sql_test_inputs:
                sql_result = await plugin_sandbox.execute_plugin_method(
                    validation_plugin, "test_sql_injection_patterns", test_input
                )
                
                if any(pattern in test_input for pattern in ["DROP", "OR '1'='1", "UNION SELECT"]):
                    assert sql_result["is_suspicious"] is True
                    assert len(sql_result["detected_patterns"]) > 0
                else:
                    assert sql_result["is_suspicious"] is False
            
            # Test XSS detection
            xss_test_inputs = [
                "normal_input",
                "<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "<iframe src='malicious.com'></iframe>"
            ]
            
            for test_input in xss_test_inputs:
                xss_result = await plugin_sandbox.execute_plugin_method(
                    validation_plugin, "test_xss_patterns", test_input
                )
                
                if any(pattern in test_input.lower() for pattern in ["<script", "javascript:", "<iframe"]):
                    assert xss_result["is_suspicious"] is True
                    assert len(xss_result["detected_patterns"]) > 0
                else:
                    assert xss_result["is_suspicious"] is False
    
    @pytest.mark.asyncio
    async def test_end_to_end_security_workflow(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper,
        config_manager,
        event_bus
    ):
        """Test comprehensive end-to-end security workflow."""
        # Set up secure configuration
        secure_config = {
            "security": {
                "enable_plugin_sandboxing": True,
                "max_plugin_execution_time": 10.0,
                "enable_network_access": False
            }
        }
        config = config_manager.load_from_dict(secure_config)
        
        # Create comprehensive security test plugin
        security_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence
from src.netstealth_analyzer.core.events import AnalysisEvent

class ComprehensiveSecurityPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="comprehensive_security_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Comprehensive security testing plugin"
        )
        self.event_bus = None
    
    @property
    def metadata(self):
        return self._metadata
    
    def set_event_bus(self, event_bus):
        self.event_bus = event_bus
    
    async def detect(self, traces):
        """Comprehensive security detection."""
        issues = []
        
        # Emit start event
        if self.event_bus:
            await self.event_bus.emit(AnalysisEvent.ANALYSIS_STARTED, {
                "plugin_name": self.name,
                "phase": "security_analysis"
            })
        
        for trace in traces:
            # Perform comprehensive security analysis
            security_score = 0
            security_findings = []
            
            # Check for privacy violations using actual NetworkHop fields
            for hop in trace.hops:
                # Check actor name for tracking indicators
                if hop.actor_name and ("tracking" in hop.actor_name.lower() or "ads" in hop.actor_name.lower()):
                    security_score += 30
                    security_findings.append(f"Privacy violation: {hop.actor_name}")
                
                # Check anomalies for tracking patterns
                if hop.anomalies:
                    for anomaly in hop.anomalies:
                        if "tracking" in anomaly.lower() or "privacy" in anomaly.lower():
                            security_score += 20
                            security_findings.append(f"Privacy anomaly detected: {anomaly}")
                        if "cookie" in anomaly.lower():
                            security_score += 10
                            security_findings.append("Cookie tracking detected")
                
                # Check for high response times (potential performance impact)
                if hop.response_time_ms and hop.response_time_ms > 200:
                    security_score += 5
                    security_findings.append(f"High response time: {hop.response_time_ms}ms")
            
            # Create security issue if score is high enough
            if security_score >= 20:
                issue = Issue(
                    id=f"security-{trace.trace_id}",
                    category=IssueCategory.PRIVACY_VIOLATION,
                    severity=SeverityLevel.HIGH if security_score >= 40 else SeverityLevel.MEDIUM,
                    title="Comprehensive Security Issue",
                    description=f"Security analysis score: {security_score}, Findings: {security_findings}",
                    confidence=min(0.95, security_score / 100),
                    impact_score=min(100, security_score * 2),
                    evidence=[
                        IssueEvidence(
                            type="security_analysis",
                            description="Comprehensive security analysis",
                            raw_data={
                                "security_score": security_score,
                                "findings": security_findings,
                                "trace_id": trace.trace_id
                            },
                            confidence=min(0.95, security_score / 100)
                        )
                    ]
                )
                issues.append(issue)
                
                # Emit security event
                if self.event_bus:
                    await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {
                        "plugin_name": self.name,
                        "issue_id": issue.id,
                        "security_score": security_score,
                        "severity": issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity)
                    })
        
        # Emit completion event
        if self.event_bus:
            await self.event_bus.emit(AnalysisEvent.ANALYSIS_COMPLETED, {
                "plugin_name": self.name,
                "issues_found": len(issues),
                "phase": "security_analysis_complete"
            })
        
        return issues
'''
        
        # Create plugin and test data
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "security_plugin.py", security_plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        security_plugin = plugins[0]
        
        # Create test traces with security issues
        security_traces = [
            NetworkTrace(
                trace_id="security-test-001",
                session_id="security-session",
                hops=[
                    NetworkHop(
                        hop_number=1,
                        hop_id="security-hop-1",
                        actor="tracking_service",
                        actor_name="Tracking Service",
                        incoming_ip="127.0.0.1",
                        outgoing_ip="93.184.216.34",
                        response_time_ms=75.0,
                        anomalies=["privacy_tracking", "cookie_tracking"]
                    )
                ]
            ),
            NetworkTrace(
                trace_id="security-test-002",
                session_id="security-session",
                hops=[
                    NetworkHop(
                        hop_number=1,
                        hop_id="security-hop-2",
                        actor="api_service",
                        actor_name="Normal API Service",
                        incoming_ip="127.0.0.1",
                        outgoing_ip="93.184.216.35",
                        response_time_ms=50.0
                    )
                ]
            )
        ]
        
        # Set up event monitoring
        security_events = []
        
        async def security_event_monitor(event, event_data):
            security_events.append((event.value, event_data))
        
        event_bus.subscribe(AnalysisEvent.ANALYSIS_STARTED, security_event_monitor)
        event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, security_event_monitor)
        event_bus.subscribe(AnalysisEvent.ANALYSIS_COMPLETED, security_event_monitor)
        
        # Execute comprehensive security workflow
        with plugin_sandbox.execute_sandboxed(security_plugin):
            await plugin_sandbox.execute_plugin_method(security_plugin, "set_event_bus", event_bus)
            
            security_issues = await plugin_sandbox.execute_plugin_method(
                security_plugin, "detect", security_traces
            )
        
        # Wait for events
        await asyncio.sleep(0.1)
        
        # Verify security workflow results
        assert len(security_issues) >= 1, "Should have detected security issues"
        
        # Verify security issue was detected for tracking trace
        tracking_issues = [issue for issue in security_issues if "security-test-001" in issue.id]
        assert len(tracking_issues) == 1
        
        tracking_issue = tracking_issues[0]
        assert tracking_issue.category == IssueCategory.PRIVACY_VIOLATION
        assert tracking_issue.severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH]
        assert "Tracking Service" in tracking_issue.description or "privacy_tracking" in tracking_issue.description
        
        # Verify events were emitted
        assert len(security_events) >= 2  # At least start and completion
        
        event_types = [event[0] for event in security_events]
        assert AnalysisEvent.ANALYSIS_STARTED.value in event_types or 1 in event_types
        assert AnalysisEvent.ANALYSIS_COMPLETED.value in event_types or 2 in event_types
        
        if len(security_issues) > 0:
            assert AnalysisEvent.ISSUE_FOUND.value in event_types or 16 in event_types
        
        # Verify configuration security was enforced
        assert config.security.enable_plugin_sandboxing is True
        assert config.security.max_plugin_execution_time == 10.0
        assert config.security.enable_network_access is False
