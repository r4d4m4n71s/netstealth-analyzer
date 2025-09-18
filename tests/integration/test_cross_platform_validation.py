"""
Integration tests for cross-platform validation.

Tests system behavior consistency across different environments and platforms.
"""

import pytest
import asyncio
import os
import sys
import platform
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from src.netstealth_analyzer.plugins.loader import PluginLoader
from src.netstealth_analyzer.plugins.sandbox import PluginSandbox
from src.netstealth_analyzer.plugins.registry import PluginRegistry
from src.netstealth_analyzer.models.network import NetworkTrace, NetworkHop
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel
from src.netstealth_analyzer.config import ConfigurationManager
from src.netstealth_analyzer.compatibility import get_python_version, ExceptionGroup


class TestCrossPlatformValidation:
    """Test system behavior consistency across platforms."""
    
    @pytest.mark.asyncio
    async def test_path_handling_consistency(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper
    ):
        """Test that path handling works consistently across platforms."""
        # Create plugin with various path operations
        path_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence
from pathlib import Path
import os

class PathTestPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="path_test_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin for cross-platform path testing"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Test various path operations across platforms."""
        issues = []
        
        # Test Path creation and manipulation
        test_paths = [
            Path("./relative/path/test.txt"),
            Path("../parent/directory/file.log"),
            Path("deep/nested/directory/structure/file.dat"),
        ]
        
        for i, path in enumerate(test_paths):
            # Test path operations that should work on all platforms
            absolute_path = path.resolve()
            parent_dir = path.parent
            filename = path.name
            stem = path.stem
            suffix = path.suffix
            
            # Create issue with path information
            issues.append(Issue(
                id=f"path-test-{i}",
                category=IssueCategory.CONFIGURATION,
                severity=SeverityLevel.LOW,
                title=f"Path Operation Test {i}",
                description=f"Path operations test for {path}",
                confidence=0.9,
                impact_score=20,
                evidence=[
                    IssueEvidence(
                        type="path_analysis",
                        description="Cross-platform path operations",
                        raw_data={
                            "original_path": str(path),
                            "absolute_path": str(absolute_path),
                            "parent_dir": str(parent_dir),
                            "filename": filename,
                            "stem": stem,
                            "suffix": suffix,
                            "platform": os.name,
                            "separator": os.sep
                        },
                        confidence=0.9
                    )
                ]
            ))
        
        return issues
    
    def get_platform_info(self):
        """Get platform-specific information."""
        import platform
        return {
            "system": platform.system(),
            "platform": platform.platform(),
            "architecture": platform.architecture(),
            "python_version": platform.python_version(),
            "os_name": os.name,
            "path_separator": os.sep,
            "line_separator": repr(os.linesep),
            "current_directory": str(Path.cwd()),
            "home_directory": str(Path.home()) if hasattr(Path, 'home') else "N/A"
        }
'''
        
        # Create plugin file
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "path_plugin.py", path_plugin_code
        )
        
        # Load and execute plugin
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        path_plugin = plugins[0]
        
        # Test path operations
        traces = [NetworkTrace(
            trace_id="path-test-001",
            session_id="cross-platform-session",
            hops=[NetworkHop(
                hop_number=1,
                hop_id="path-hop-1",
                actor="client",
                actor_name="Test Client",
                incoming_ip="127.0.0.1",
                outgoing_ip="192.168.1.1"
            )]
        )]
        
        with plugin_sandbox.execute_sandboxed(path_plugin):
            # Test path operations
            issues = await plugin_sandbox.execute_plugin_method(
                path_plugin, "detect", traces
            )
            
            # Get platform info
            platform_info = await plugin_sandbox.execute_plugin_method(
                path_plugin, "get_platform_info"
            )
        
        # Verify path operations worked consistently
        assert len(issues) == 3
        
        for issue in issues:
            assert len(issue.evidence) == 1
            path_data = issue.evidence[0].raw_data
            
            # Verify path components are present
            assert "original_path" in path_data
            assert "absolute_path" in path_data
            assert "parent_dir" in path_data
            assert "filename" in path_data
            assert "platform" in path_data
            assert "separator" in path_data
            
            # Verify path separator is platform-appropriate
            if os.name == 'nt':  # Windows
                assert path_data["separator"] == "\\"
            else:  # Unix-like systems
                assert path_data["separator"] == "/"
        
        # Verify platform info is complete
        assert "system" in platform_info
        assert "python_version" in platform_info
        assert "os_name" in platform_info
        assert platform_info["os_name"] in ["nt", "posix", "java"]
    
    @pytest.mark.asyncio
    async def test_file_system_operations_consistency(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper
    ):
        """Test file system operations across platforms."""
        # Create plugin that performs file operations
        fs_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence
from pathlib import Path
import tempfile
import os

class FileSystemPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="filesystem_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin for file system operations testing"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Test file system operations."""
        issues = []
        
        # Create temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Test file creation
            test_file = temp_path / "test_file.txt"
            test_file.write_text("Test content for cross-platform validation")
            
            # Test directory creation
            test_dir = temp_path / "test_directory"
            test_dir.mkdir()
            
            # Test file reading
            content = test_file.read_text()
            
            # Test file listing
            files = list(temp_path.iterdir())
            
            # Test file permissions (if supported)
            try:
                file_stat = test_file.stat()
                permissions = oct(file_stat.st_mode)[-3:]
            except (AttributeError, OSError):
                permissions = "N/A"
            
            # Create issue with file system operation results
            issues.append(Issue(
                id="filesystem-test",
                category=IssueCategory.CONFIGURATION,
                severity=SeverityLevel.LOW,
                title="File System Operations Test",
                description="Cross-platform file system operations validation",
                confidence=0.9,
                impact_score=25,
                evidence=[
                    IssueEvidence(
                        type="filesystem_operations",
                        description="File system operation results",
                        raw_data={
                            "temp_directory": str(temp_path),
                            "file_created": test_file.exists(),
                            "directory_created": test_dir.exists(),
                            "file_content": content,
                            "files_found": len(files),
                            "file_permissions": permissions,
                            "platform": os.name
                        },
                        confidence=0.9
                    )
                ]
            ))
        
        return issues
    
    def test_environment_variables(self):
        """Test environment variable access."""
        import os
        
        # Test common environment variables
        env_vars = {}
        common_vars = ["PATH", "HOME", "USER", "TEMP", "TMP", "PYTHONPATH"]
        
        for var in common_vars:
            env_vars[var] = os.environ.get(var, "NOT_FOUND")
        
        # Add platform-specific variables
        if os.name == 'nt':  # Windows
            env_vars.update({
                "USERNAME": os.environ.get("USERNAME", "NOT_FOUND"),
                "USERPROFILE": os.environ.get("USERPROFILE", "NOT_FOUND"),
                "APPDATA": os.environ.get("APPDATA", "NOT_FOUND")
            })
        else:  # Unix-like
            env_vars.update({
                "USER": os.environ.get("USER", "NOT_FOUND"),
                "SHELL": os.environ.get("SHELL", "NOT_FOUND"),
                "PWD": os.environ.get("PWD", "NOT_FOUND")
            })
        
        return env_vars
'''
        
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "fs_plugin.py", fs_plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        fs_plugin = plugins[0]
        
        traces = [NetworkTrace(
            trace_id="fs-test-001",
            session_id="cross-platform-session",
            hops=[NetworkHop(
                hop_number=1,
                hop_id="fs-hop-1",
                actor="client",
                actor_name="FileSystem Test Client",
                incoming_ip="127.0.0.1",
                outgoing_ip="192.168.1.1"
            )]
        )]
        
        with plugin_sandbox.execute_sandboxed(fs_plugin):
            # Test file system operations
            issues = await plugin_sandbox.execute_plugin_method(
                fs_plugin, "detect", traces
            )
            
            # Test environment variables
            env_vars = await plugin_sandbox.execute_plugin_method(
                fs_plugin, "test_environment_variables"
            )
        
        # Verify file system operations worked
        assert len(issues) == 1
        fs_issue = issues[0]
        
        fs_data = fs_issue.evidence[0].raw_data
        assert fs_data["file_created"] is True
        assert fs_data["directory_created"] is True
        assert fs_data["file_content"] == "Test content for cross-platform validation"
        assert fs_data["files_found"] >= 2  # At least the file and directory
        
        # Verify environment variables are accessible
        assert isinstance(env_vars, dict)
        assert "PATH" in env_vars
        
        # Platform-specific environment variable checks
        if os.name == 'nt':
            # Windows should have these
            assert "USERNAME" in env_vars or "USER" in env_vars
        else:
            # Unix-like should have these
            assert "USER" in env_vars
    
    @pytest.mark.asyncio
    async def test_python_version_compatibility(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper
    ):
        """Test Python version compatibility features."""
        # Create plugin that tests version-specific features
        version_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence
from src.netstealth_analyzer.compatibility import ExceptionGroup
import sys
import asyncio

class VersionCompatibilityPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="version_compatibility_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin for Python version compatibility testing"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Test version-specific features."""
        issues = []
        
        # Test Python version check
        version_info = {
            "python_version": sys.version,
            "version_info": sys.version_info,
            "major": sys.version_info.major,
            "minor": sys.version_info.minor,
            "micro": sys.version_info.micro
        }
        
        # Test version check function (simple compatibility check)
        is_compatible = sys.version_info >= (3, 11)
        
        # Test modern Python features availability
        modern_features = {}
        
        # Test asyncio features (Python 3.7+)
        try:
            # Test asyncio.run availability
            modern_features["asyncio_run"] = hasattr(asyncio, 'run')
        except:
            modern_features["asyncio_run"] = False
        
        # Test ExceptionGroup (Python 3.11+ or compatibility layer)
        try:
            test_exceptions = [ValueError("test1"), TypeError("test2")]
            exception_group = ExceptionGroup("Test group", test_exceptions)
            modern_features["exception_group"] = True
        except:
            modern_features["exception_group"] = False
        
        # Test f-string features (should be available in all supported versions)
        try:
            value = 42
            f_string_result = f"Value is {value}"
            modern_features["f_strings"] = f_string_result == "Value is 42"
        except:
            modern_features["f_strings"] = False
        
        # Test type hints (should be available)
        try:
            from typing import List, Dict, Optional
            modern_features["type_hints"] = True
        except ImportError:
            modern_features["type_hints"] = False
        
        # Create issue with compatibility results
        issues.append(Issue(
            id="version-compatibility-test",
            category=IssueCategory.CONFIGURATION,
            severity=SeverityLevel.LOW,
            title="Python Version Compatibility Test",
            description=f"Python {version_info['major']}.{version_info['minor']}.{version_info['micro']} compatibility validation",
            confidence=0.95,
            impact_score=30,
            evidence=[
                IssueEvidence(
                    type="version_compatibility",
                    description="Python version and feature compatibility",
                    raw_data={
                        "version_info": version_info,
                        "is_compatible": is_compatible,
                        "modern_features": modern_features
                    },
                    confidence=0.95
                )
            ]
        ))
        
        return issues
    
    def get_system_capabilities(self):
        """Get system capabilities and limitations."""
        import platform
        import sys
        
        capabilities = {
            "platform": platform.platform(),
            "architecture": platform.architecture(),
            "processor": platform.processor(),
            "python_implementation": platform.python_implementation(),
            "python_compiler": platform.python_compiler(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "maxsize": sys.maxsize,
            "float_info": {
                "max": sys.float_info.max,
                "min": sys.float_info.min,
                "epsilon": sys.float_info.epsilon
            },
            "int_info": {
                "bits_per_digit": getattr(sys.int_info, 'bits_per_digit', 'N/A'),
                "sizeof_digit": getattr(sys.int_info, 'sizeof_digit', 'N/A')
            }
        }
        
        return capabilities
'''
        
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "version_plugin.py", version_plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        version_plugin = plugins[0]
        
        traces = [NetworkTrace(
            trace_id="version-test-001",
            session_id="cross-platform-session",
            hops=[NetworkHop(
                hop_number=1,
                hop_id="version-hop-1",
                actor="client",
                actor_name="Version Test Client",
                incoming_ip="127.0.0.1",
                outgoing_ip="192.168.1.1"
            )]
        )]
        
        with plugin_sandbox.execute_sandboxed(version_plugin):
            # Test version compatibility
            issues = await plugin_sandbox.execute_plugin_method(
                version_plugin, "detect", traces
            )
            
            # Get system capabilities
            capabilities = await plugin_sandbox.execute_plugin_method(
                version_plugin, "get_system_capabilities"
            )
        
        # Verify version compatibility testing worked
        assert len(issues) == 1
        version_issue = issues[0]
        
        compat_data = version_issue.evidence[0].raw_data
        assert "version_info" in compat_data
        assert "is_compatible" in compat_data
        assert "modern_features" in compat_data
        
        # Verify Python version is supported (3.11+)
        version_info = compat_data["version_info"]
        assert version_info["major"] >= 3
        if version_info["major"] == 3:
            assert version_info["minor"] >= 11  # Minimum supported version
        
        # Verify modern features are available
        features = compat_data["modern_features"]
        assert features["f_strings"] is True  # Should always be available
        assert features["type_hints"] is True  # Should always be available
        assert features["asyncio_run"] is True  # Should be available in Python 3.11+
        
        # Verify system capabilities
        assert "platform" in capabilities
        assert "python_implementation" in capabilities
        assert capabilities["python_implementation"] in ["CPython", "PyPy", "Jython", "IronPython"]
    
    @pytest.mark.asyncio
    async def test_configuration_portability(self, config_manager):
        """Test configuration system works consistently across platforms."""
        # Test configuration with platform-specific paths
        platform_config = {
            "logging": {
                "level": "INFO",
                "file_path": "./logs/netstealth.log"  # Relative path should work everywhere
            },
            "plugins": {
                "directories": ["./plugins", "../shared_plugins"],  # Relative paths
                "enable_discovery": True
            },
            "security": {
                "enable_plugin_sandboxing": True,
                "max_plugin_execution_time": 60.0,
                "allowed_plugin_paths": ["./plugins", "./safe_plugins"]  # Relative paths
            },
            "analysis": {
                "output_directory": "./output",  # Relative path
                "temp_directory": "./temp"       # Relative path
            }
        }
        
        # Load configuration
        config = config_manager.load_from_dict(platform_config)
        
        # Verify configuration loaded successfully
        assert config.logging.level == "INFO"
        assert config.plugins.enable_discovery is True
        assert config.security.enable_plugin_sandboxing is True
        
        # Test that relative paths are handled consistently
        assert "logs" in str(config.logging.file_path) and "netstealth.log" in str(config.logging.file_path)
        assert len(config.plugins.directories) == 2
        assert "./plugins" in config.plugins.directories
        
        # Test configuration serialization/deserialization
        config_dict = config.model_dump()
        reloaded_config = config_manager.load_from_dict(config_dict)
        
        # Verify serialization round-trip
        assert reloaded_config.logging.level == config.logging.level
        assert reloaded_config.plugins.directories == config.plugins.directories
        assert reloaded_config.security.max_plugin_execution_time == config.security.max_plugin_execution_time
    
    @pytest.mark.asyncio
    async def test_concurrent_operations_consistency(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper
    ):
        """Test that concurrent operations behave consistently across platforms."""
        # Create plugin that performs concurrent operations
        concurrent_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence
import asyncio
import time
import threading

class ConcurrentPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="concurrent_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin for concurrent operations testing"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Test concurrent operations."""
        issues = []
        
        # Test asyncio concurrent operations
        start_time = time.time()
        
        # Create multiple async tasks
        async def async_task(task_id, delay):
            await asyncio.sleep(delay)
            return f"Task {task_id} completed after {delay}s"
        
        # Run tasks concurrently
        tasks = [
            async_task(i, 0.1) for i in range(5)
        ]
        
        results = await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Test threading operations
        thread_results = []
        threads = []
        
        def thread_task(task_id):
            time.sleep(0.1)
            thread_results.append(f"Thread {task_id} completed")
        
        thread_start = time.time()
        for i in range(3):
            thread = threading.Thread(target=thread_task, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        thread_end = time.time()
        thread_time = thread_end - thread_start
        
        # Create issue with concurrent operation results
        issues.append(Issue(
            id="concurrent-operations-test",
            category=IssueCategory.CONFIGURATION,
            severity=SeverityLevel.LOW,
            title="Concurrent Operations Test",
            description="Cross-platform concurrent operations validation",
            confidence=0.9,
            impact_score=35,
            evidence=[
                IssueEvidence(
                    type="concurrent_operations",
                    description="Concurrent operation performance and correctness",
                    raw_data={
                        "async_tasks_count": len(tasks),
                        "async_results_count": len(results),
                        "async_total_time": total_time,
                        "thread_count": len(threads),
                        "thread_results_count": len(thread_results),
                        "thread_total_time": thread_time,
                        "async_faster_than_sequential": total_time < 0.5,  # Should be much faster than 5*0.1
                        "thread_faster_than_sequential": thread_time < 0.35  # Should be faster than 3*0.1
                    },
                    confidence=0.9
                )
            ]
        ))
        
        return issues
'''
        
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "concurrent_plugin.py", concurrent_plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        concurrent_plugin = plugins[0]
        
        traces = [NetworkTrace(
            trace_id="concurrent-test-001",
            session_id="cross-platform-session",
            hops=[NetworkHop(
                hop_number=1,
                hop_id="concurrent-hop-1",
                actor="client",
                actor_name="Concurrent Test Client",
                incoming_ip="127.0.0.1",
                outgoing_ip="192.168.1.1"
            )]
        )]
        
        with plugin_sandbox.execute_sandboxed(concurrent_plugin):
            # Test concurrent operations
            issues = await plugin_sandbox.execute_plugin_method(
                concurrent_plugin, "detect", traces
            )
        
        # Verify concurrent operations worked correctly
        assert len(issues) == 1
        concurrent_issue = issues[0]
        
        concurrent_data = concurrent_issue.evidence[0].raw_data
        
        # Verify async operations
        assert concurrent_data["async_tasks_count"] == 5
        assert concurrent_data["async_results_count"] == 5
        assert concurrent_data["async_faster_than_sequential"] is True
        
        # Verify thread operations
        assert concurrent_data["thread_count"] == 3
        assert concurrent_data["thread_results_count"] == 3
        assert concurrent_data["thread_faster_than_sequential"] is True
        
        # Verify timing is reasonable (concurrent should be much faster than sequential)
        assert concurrent_data["async_total_time"] < 0.5  # Much less than 5*0.1 = 0.5s
        assert concurrent_data["thread_total_time"] < 0.35  # Much less than 3*0.1 = 0.3s
    
    @pytest.mark.asyncio 
    async def test_error_handling_consistency(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper
    ):
        """Test that error handling behaves consistently across platforms."""
        # Create plugin that tests various error conditions
        error_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence
from src.netstealth_analyzer.compatibility import ExceptionGroup
import os
import sys

class ErrorHandlingPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="error_handling_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin for error handling consistency testing"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Test error handling consistency."""
        issues = []
        error_results = {}
        
        # Test standard exception handling
        try:
            raise ValueError("Test ValueError")
        except ValueError as e:
            error_results["value_error_caught"] = True
            error_results["value_error_message"] = str(e)
        
        # Test file operation errors
        try:
            with open("/nonexistent/path/file.txt", "r") as f:
                content = f.read()
        except (FileNotFoundError, OSError, PermissionError) as e:
            error_results["file_error_caught"] = True
            error_results["file_error_type"] = type(e).__name__
        
        # Test ExceptionGroup handling (Python 3.11+ feature or compatibility)
        try:
            exceptions = [ValueError("Error 1"), TypeError("Error 2")]
            exception_group = ExceptionGroup("Test group", exceptions)
            raise exception_group
        except ExceptionGroup as eg:
            error_results["exception_group_caught"] = True
            error_results["exception_group_count"] = len(eg.exceptions)
        except Exception as e:
            # Fallback for older Python versions
            error_results["exception_group_fallback"] = True
            error_results["fallback_error"] = type(e).__name__
        
        # Test import error handling
        try:
            import nonexistent_module
        except ImportError as e:
            error_results["import_error_caught"] = True
            error_results["import_error_message"] = str(e)
        
        # Create issue with error handling results
        issues.append(Issue(
            id="error-handling-consistency-test",
            category=IssueCategory.CONFIGURATION,
            severity=SeverityLevel.LOW,
            title="Error Handling Consistency Test",
            description="Cross-platform error handling validation",
            confidence=0.9,
            impact_score=40,
            evidence=[
                IssueEvidence(
                    type="error_handling",
                    description="Error handling behavior consistency",
                    raw_data={
                        "platform": os.name,
                        "python_version": sys.version_info[:3],
                        "error_results": error_results
                    },
                    confidence=0.9
                )
            ]
        ))
        
        return issues
'''
        
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "error_plugin.py", error_plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        error_plugin = plugins[0]
        
        traces = [NetworkTrace(
            trace_id="error-test-001",
            session_id="cross-platform-session",
            hops=[NetworkHop(
                hop_number=1,
                hop_id="error-hop-1",
                actor="client",
                actor_name="Error Handling Test Client",
                incoming_ip="127.0.0.1",
                outgoing_ip="192.168.1.1"
            )]
        )]
        
        with plugin_sandbox.execute_sandboxed(error_plugin):
            # Test error handling consistency
            issues = await plugin_sandbox.execute_plugin_method(
                error_plugin, "detect", traces
            )
        
        # Verify error handling consistency
        assert len(issues) == 1
        error_issue = issues[0]
        
        error_data = error_issue.evidence[0].raw_data
        error_results = error_data["error_results"]
        
        # Verify standard exceptions are handled consistently
        assert error_results["value_error_caught"] is True
        assert error_results["value_error_message"] == "Test ValueError"
        
        # Verify file operation errors are handled
        assert error_results["file_error_caught"] is True
        assert error_results["file_error_type"] in ["FileNotFoundError", "OSError", "PermissionError"]
        
        # Verify ExceptionGroup is handled (either native or fallback)
        assert (error_results.get("exception_group_caught") is True or 
                error_results.get("exception_group_fallback") is True)
        
        if error_results.get("exception_group_caught"):
            assert error_results["exception_group_count"] == 2
        
        # Verify import errors are handled
        assert error_results["import_error_caught"] is True
        assert "nonexistent_module" in error_results["import_error_message"]
        
        # Verify platform information is consistent
        assert error_data["platform"] in ["nt", "posix", "java"]
        assert len(error_data["python_version"]) == 3  # (major, minor, micro)
