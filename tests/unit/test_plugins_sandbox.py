"""
Unit tests for NetStealth Analyzer plugin sandbox system.

Tests security isolation, resource limits, execution timeouts, and plugin
containment mechanisms.
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Any, Dict, Optional
from contextlib import contextmanager

from src.netstealth_analyzer.plugins.sandbox import (
    PluginSandbox,
    get_global_sandbox,
    set_global_sandbox,
    reset_global_sandbox,
    execute_plugin_safely,
    sandboxed_execution,
)
from src.netstealth_analyzer.plugins.base import (
    IPlugin,
    PluginMetadata,
    PluginType,
    PluginStatus,
    PluginExecutionError,
)


# Mock plugin classes for testing
class MockPlugin(IPlugin):
    """Mock plugin for testing."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, sandboxed: bool = True):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="test_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Test plugin",
            sandboxed=sandboxed
        )
        self.execution_count = 0
        self.last_args = None
        self.last_kwargs = None
    
    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata
    
    def test_method(self, *args, **kwargs):
        """Test method for sandbox execution."""
        self.execution_count += 1
        self.last_args = args
        self.last_kwargs = kwargs
        return f"executed with {args} {kwargs}"
    
    async def async_test_method(self, *args, **kwargs):
        """Async test method for sandbox execution."""
        await asyncio.sleep(0.01)  # Small delay to simulate async work
        self.execution_count += 1
        self.last_args = args
        self.last_kwargs = kwargs
        return f"async executed with {args} {kwargs}"
    
    def slow_method(self, duration: float = 1.0):
        """Method that takes time to execute."""
        time.sleep(duration)
        return "slow execution complete"
    
    async def slow_async_method(self, duration: float = 1.0):
        """Async method that takes time to execute."""
        await asyncio.sleep(duration)
        return "slow async execution complete"
    
    def memory_intensive_method(self, size_mb: int = 10):
        """Method that uses memory (simulated)."""
        # Simulate memory usage by creating a large list
        data = [0] * (size_mb * 1024 * 100)  # Approximate MB
        return f"used {len(data)} memory units"
    
    def error_method(self):
        """Method that raises an error."""
        raise ValueError("Test error from plugin")
    
    async def async_error_method(self):
        """Async method that raises an error."""
        await asyncio.sleep(0.01)
        raise RuntimeError("Async test error from plugin")


class NonSandboxedPlugin(MockPlugin):
    """Mock plugin that doesn't require sandboxing."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config, sandboxed=False)


class TestPluginSandbox:
    """Test PluginSandbox class."""
    
    def test_sandbox_initialization(self):
        """Test PluginSandbox initialization with default values."""
        sandbox = PluginSandbox()
        
        assert sandbox.max_memory_mb == 100
        assert sandbox.max_execution_time == 30.0
        assert sandbox.max_cpu_time == 10.0
        assert sandbox.allow_network is True
        assert sandbox.allow_file_access is True
        assert sandbox._start_time is None
        assert sandbox._start_memory is None
    
    def test_sandbox_custom_initialization(self):
        """Test PluginSandbox initialization with custom values."""
        sandbox = PluginSandbox(
            max_memory_mb=50,
            max_execution_time=15.0,
            max_cpu_time=5.0,
            allow_network=False,
            allow_file_access=False
        )
        
        assert sandbox.max_memory_mb == 50
        assert sandbox.max_execution_time == 15.0
        assert sandbox.max_cpu_time == 5.0
        assert sandbox.allow_network is False
        assert sandbox.allow_file_access is False
    
    def test_get_sandbox_config(self):
        """Test getting sandbox configuration."""
        sandbox = PluginSandbox(
            max_memory_mb=75,
            max_execution_time=20.0,
            max_cpu_time=8.0,
            allow_network=True,
            allow_file_access=False
        )
        
        config = sandbox.get_sandbox_config()
        
        assert config['max_memory_mb'] == 75
        assert config['max_execution_time'] == 20.0
        assert config['max_cpu_time'] == 8.0
        assert config['allow_network'] is True
        assert config['allow_file_access'] is False
    
    def test_execute_sandboxed_non_sandboxed_plugin(self):
        """Test executing non-sandboxed plugin (should pass through)."""
        sandbox = PluginSandbox()
        plugin = NonSandboxedPlugin()
        
        executed = False
        
        with sandbox.execute_sandboxed(plugin):
            executed = True
        
        assert executed is True
    
    @pytest.mark.asyncio
    async def test_execute_sandboxed_basic(self):
        """Test basic sandboxed execution."""
        sandbox = PluginSandbox()
        plugin = MockPlugin()
        
        executed = False
        
        with sandbox.execute_sandboxed(plugin):
            executed = True
        
        assert executed is True
    
    @patch('src.netstealth_analyzer.plugins.sandbox.resource')
    def test_setup_resource_limits_with_resource_module(self, mock_resource):
        """Test setting up resource limits when resource module is available."""
        # Mock resource module availability
        mock_resource.RLIMIT_AS = 9
        mock_resource.RLIMIT_CPU = 0
        mock_resource.getrlimit.side_effect = [(1000, 2000), (10, 20)]
        
        sandbox = PluginSandbox(max_memory_mb=100, max_cpu_time=5.0)
        
        with patch('src.netstealth_analyzer.plugins.sandbox.HAS_RESOURCE', True):
            old_limits = sandbox._setup_resource_limits()
        
        assert 'memory' in old_limits
        assert 'cpu' in old_limits
        assert old_limits['memory'] == (1000, 2000)
        assert old_limits['cpu'] == (10, 20)
        
        # Verify setrlimit was called
        expected_memory_limit = 100 * 1024 * 1024  # 100MB in bytes
        mock_resource.setrlimit.assert_any_call(9, (expected_memory_limit, 2000))
        mock_resource.setrlimit.assert_any_call(0, (5, 20))
    
    @patch('src.netstealth_analyzer.plugins.sandbox.resource')
    def test_restore_resource_limits(self, mock_resource):
        """Test restoring resource limits."""
        mock_resource.RLIMIT_AS = 9
        mock_resource.RLIMIT_CPU = 0
        
        sandbox = PluginSandbox()
        old_limits = {
            'memory': (1000, 2000),
            'cpu': (10, 20)
        }
        
        with patch('src.netstealth_analyzer.plugins.sandbox.HAS_RESOURCE', True):
            sandbox._restore_resource_limits(old_limits)
        
        mock_resource.setrlimit.assert_any_call(9, (1000, 2000))
        mock_resource.setrlimit.assert_any_call(0, (10, 20))
    
    def test_start_monitoring(self):
        """Test starting resource monitoring."""
        sandbox = PluginSandbox()
        
        start_time_before = time.time()
        sandbox._start_monitoring()
        start_time_after = time.time()
        
        assert sandbox._start_time is not None
        assert start_time_before <= sandbox._start_time <= start_time_after
    
    def test_check_resource_usage_no_monitoring(self):
        """Test resource usage check when monitoring wasn't started."""
        sandbox = PluginSandbox()
        
        # Should not raise any exception
        sandbox._check_resource_usage("test_plugin")
    
    def test_check_resource_usage_execution_time_exceeded(self):
        """Test resource usage check when execution time is exceeded."""
        sandbox = PluginSandbox(max_execution_time=0.1)
        
        # Simulate execution that took longer than allowed
        sandbox._start_time = time.time() - 0.2  # 200ms ago
        
        with pytest.raises(PluginExecutionError, match="exceeded execution time"):
            sandbox._check_resource_usage("test_plugin")
    
    @pytest.mark.asyncio
    async def test_timeout_handler(self):
        """Test timeout handler."""
        sandbox = PluginSandbox()
        
        start_time = time.time()
        
        with pytest.raises(asyncio.TimeoutError, match="execution timed out"):
            await sandbox._timeout_handler(0.1, "test_plugin")
        
        elapsed = time.time() - start_time
        assert elapsed >= 0.1  # Should have waited at least 100ms
    
    @pytest.mark.asyncio
    async def test_execute_plugin_method_sync(self):
        """Test executing synchronous plugin method."""
        sandbox = PluginSandbox()
        plugin = MockPlugin()
        
        result = await sandbox.execute_plugin_method(
            plugin, "test_method", "arg1", "arg2", kwarg1="value1"
        )
        
        assert result == "executed with ('arg1', 'arg2') {'kwarg1': 'value1'}"
        assert plugin.execution_count == 1
        assert plugin.last_args == ("arg1", "arg2")
        assert plugin.last_kwargs == {"kwarg1": "value1"}
    
    @pytest.mark.asyncio
    async def test_execute_plugin_method_async(self):
        """Test executing asynchronous plugin method."""
        sandbox = PluginSandbox()
        plugin = MockPlugin()
        
        result = await sandbox.execute_plugin_method(
            plugin, "async_test_method", "arg1", kwarg1="value1"
        )
        
        assert result == "async executed with ('arg1',) {'kwarg1': 'value1'}"
        assert plugin.execution_count == 1
        assert plugin.last_args == ("arg1",)
        assert plugin.last_kwargs == {"kwarg1": "value1"}
    
    @pytest.mark.asyncio
    async def test_execute_plugin_method_nonexistent(self):
        """Test executing non-existent plugin method."""
        sandbox = PluginSandbox()
        plugin = MockPlugin()
        
        with pytest.raises(PluginExecutionError, match="does not have method"):
            await sandbox.execute_plugin_method(plugin, "nonexistent_method")
    
    @pytest.mark.asyncio
    async def test_execute_plugin_method_not_callable(self):
        """Test executing non-callable plugin attribute."""
        sandbox = PluginSandbox()
        plugin = MockPlugin()
        plugin.not_callable = "not a method"
        
        with pytest.raises(PluginExecutionError, match="is not callable"):
            await sandbox.execute_plugin_method(plugin, "not_callable")
    
    @pytest.mark.asyncio
    async def test_execute_plugin_method_with_error(self):
        """Test executing plugin method that raises an error."""
        sandbox = PluginSandbox()
        plugin = MockPlugin()
        
        with pytest.raises(PluginExecutionError, match="execution failed"):
            await sandbox.execute_plugin_method(plugin, "error_method")
    
    @pytest.mark.asyncio
    async def test_execute_plugin_method_with_async_error(self):
        """Test executing async plugin method that raises an error."""
        sandbox = PluginSandbox()
        plugin = MockPlugin()
        
        with pytest.raises(PluginExecutionError, match="execution failed"):
            await sandbox.execute_plugin_method(plugin, "async_error_method")
    
    @pytest.mark.asyncio
    async def test_execute_plugin_method_with_timeout(self):
        """Test executing plugin method with timeout."""
        sandbox = PluginSandbox(max_execution_time=0.1)
        plugin = MockPlugin()
        
        with pytest.raises(PluginExecutionError, match="exceeded execution time"):
            await sandbox.execute_plugin_method(plugin, "slow_async_method", 0.2)
    
    @pytest.mark.asyncio
    async def test_execute_sandboxed_with_memory_error(self):
        """Test sandboxed execution with memory error."""
        sandbox = PluginSandbox()
        plugin = MockPlugin()
        
        with patch('src.netstealth_analyzer.plugins.sandbox.PluginSandbox._check_resource_usage') as mock_check:
            mock_check.side_effect = MemoryError("Out of memory")
            
            with pytest.raises(PluginExecutionError, match="exceeded memory limit"):
                with sandbox.execute_sandboxed(plugin):
                    pass
    
    @pytest.mark.asyncio
    async def test_execute_sandboxed_with_timeout_error(self):
        """Test sandboxed execution with timeout error."""
        sandbox = PluginSandbox(max_execution_time=0.1)
        plugin = MockPlugin()
        
        with pytest.raises(PluginExecutionError, match="exceeded execution time"):
            with sandbox.execute_sandboxed(plugin):
                await asyncio.sleep(0.2)
    
    @pytest.mark.asyncio
    async def test_execute_sandboxed_cleanup_on_exception(self):
        """Test that sandbox cleanup happens even when exception occurs."""
        sandbox = PluginSandbox()
        plugin = MockPlugin()
        
        with patch.object(sandbox, '_restore_resource_limits') as mock_restore:
            with patch.object(sandbox, '_setup_resource_limits', return_value={}):
                try:
                    with sandbox.execute_sandboxed(plugin):
                        raise ValueError("Test exception")
                except PluginExecutionError:
                    pass  # Expected to be wrapped in PluginExecutionError
                
                # Cleanup should have been called
                mock_restore.assert_called_once()


class TestGlobalSandbox:
    """Test global sandbox functions."""
    
    def setup_method(self):
        """Reset global sandbox before each test."""
        reset_global_sandbox()
    
    def teardown_method(self):
        """Reset global sandbox after each test."""
        reset_global_sandbox()
    
    def test_get_global_sandbox_creates_instance(self):
        """Test that get_global_sandbox creates instance if none exists."""
        sandbox = get_global_sandbox()
        
        assert isinstance(sandbox, PluginSandbox)
        assert sandbox.max_memory_mb == 100  # Default value
    
    def test_get_global_sandbox_returns_same_instance(self):
        """Test that get_global_sandbox returns the same instance."""
        sandbox1 = get_global_sandbox()
        sandbox2 = get_global_sandbox()
        
        assert sandbox1 is sandbox2
    
    def test_set_global_sandbox(self):
        """Test setting custom global sandbox."""
        custom_sandbox = PluginSandbox(max_memory_mb=200)
        set_global_sandbox(custom_sandbox)
        
        retrieved_sandbox = get_global_sandbox()
        
        assert retrieved_sandbox is custom_sandbox
        assert retrieved_sandbox.max_memory_mb == 200
    
    def test_reset_global_sandbox(self):
        """Test resetting global sandbox."""
        # Get initial sandbox
        sandbox1 = get_global_sandbox()
        
        # Reset and get new sandbox
        reset_global_sandbox()
        sandbox2 = get_global_sandbox()
        
        assert sandbox1 is not sandbox2


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def setup_method(self):
        """Reset global sandbox before each test."""
        reset_global_sandbox()
    
    def teardown_method(self):
        """Reset global sandbox after each test."""
        reset_global_sandbox()
    
    @pytest.mark.asyncio
    async def test_execute_plugin_safely_with_global_sandbox(self):
        """Test execute_plugin_safely using global sandbox."""
        plugin = MockPlugin()
        
        result = await execute_plugin_safely(
            plugin, "test_method", "arg1", kwarg1="value1"
        )
        
        assert result == "executed with ('arg1',) {'kwarg1': 'value1'}"
        assert plugin.execution_count == 1
    
    @pytest.mark.asyncio
    async def test_execute_plugin_safely_with_custom_sandbox(self):
        """Test execute_plugin_safely with custom sandbox."""
        plugin = MockPlugin()
        custom_sandbox = PluginSandbox(max_memory_mb=200)
        
        result = await execute_plugin_safely(
            plugin, "test_method", "arg1", sandbox=custom_sandbox, kwarg1="value1"
        )
        
        assert result == "executed with ('arg1',) {'kwarg1': 'value1'}"
        assert plugin.execution_count == 1
    
    @pytest.mark.asyncio
    async def test_sandboxed_execution_context_manager_global(self):
        """Test sandboxed_execution context manager with global sandbox."""
        plugin = MockPlugin()
        
        executed = False
        with sandboxed_execution(plugin):
            executed = True
        
        assert executed is True
    
    @pytest.mark.asyncio
    async def test_sandboxed_execution_context_manager_custom(self):
        """Test sandboxed_execution context manager with custom sandbox."""
        plugin = MockPlugin()
        custom_sandbox = PluginSandbox(max_memory_mb=200)
        
        executed = False
        with sandboxed_execution(plugin, sandbox=custom_sandbox):
            executed = True
        
        assert executed is True


class TestSandboxIntegration:
    """Integration tests for sandbox functionality."""
    
    @pytest.mark.asyncio
    async def test_full_plugin_execution_workflow(self):
        """Test complete plugin execution workflow with sandbox."""
        # Create sandbox with specific limits
        sandbox = PluginSandbox(
            max_memory_mb=50,
            max_execution_time=1.0,
            max_cpu_time=0.5
        )
        
        # Create plugin
        plugin = MockPlugin()
        
        # Execute multiple methods
        result1 = await sandbox.execute_plugin_method(plugin, "test_method", "test")
        result2 = await sandbox.execute_plugin_method(plugin, "async_test_method", "async")
        
        assert "test" in result1
        assert "async" in result2
        assert plugin.execution_count == 2
    
    @pytest.mark.asyncio
    async def test_sandbox_isolation_between_plugins(self):
        """Test that sandbox properly isolates different plugins."""
        sandbox = PluginSandbox()
        
        plugin1 = MockPlugin()
        plugin1._metadata.name = "plugin1"
        
        plugin2 = MockPlugin()
        plugin2._metadata.name = "plugin2"
        
        # Execute methods on both plugins
        await sandbox.execute_plugin_method(plugin1, "test_method", "p1")
        await sandbox.execute_plugin_method(plugin2, "test_method", "p2")
        
        # Verify isolation
        assert plugin1.execution_count == 1
        assert plugin2.execution_count == 1
        assert plugin1.last_args == ("p1",)
        assert plugin2.last_args == ("p2",)
    
    @pytest.mark.asyncio
    async def test_sandbox_configuration_persistence(self):
        """Test that sandbox configuration persists across operations."""
        sandbox = PluginSandbox(
            max_memory_mb=75,
            max_execution_time=25.0,
            allow_network=False
        )
        
        # Configuration should remain the same
        config1 = sandbox.get_sandbox_config()
        
        # Execute some operations
        plugin = MockPlugin()
        with sandbox.execute_sandboxed(plugin):
            pass
        
        config2 = sandbox.get_sandbox_config()
        
        assert config1 == config2
        assert config1['max_memory_mb'] == 75
        assert config1['max_execution_time'] == 25.0
        assert config1['allow_network'] is False
    
    @pytest.mark.asyncio
    async def test_concurrent_plugin_execution(self):
        """Test concurrent execution of multiple plugins."""
        sandbox = PluginSandbox()
        
        plugins = [MockPlugin() for _ in range(5)]
        for i, plugin in enumerate(plugins):
            plugin._metadata.name = f"plugin_{i}"
        
        # Execute all plugins concurrently
        tasks = [
            sandbox.execute_plugin_method(plugin, "async_test_method", f"arg_{i}")
            for i, plugin in enumerate(plugins)
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Verify all executions completed
        assert len(results) == 5
        for i, (result, plugin) in enumerate(zip(results, plugins)):
            assert f"arg_{i}" in result
            assert plugin.execution_count == 1
    
    @pytest.mark.asyncio
    async def test_error_handling_in_concurrent_execution(self):
        """Test error handling when some plugins fail in concurrent execution."""
        sandbox = PluginSandbox()
        
        good_plugin = MockPlugin()
        good_plugin._metadata.name = "good_plugin"
        
        bad_plugin = MockPlugin()
        bad_plugin._metadata.name = "bad_plugin"
        
        # Execute one good and one bad plugin concurrently
        tasks = [
            sandbox.execute_plugin_method(good_plugin, "test_method", "good"),
            sandbox.execute_plugin_method(bad_plugin, "error_method")
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # First should succeed, second should fail
        assert "good" in results[0]
        assert isinstance(results[1], PluginExecutionError)
        assert good_plugin.execution_count == 1
        assert bad_plugin.execution_count == 0  # Error method doesn't increment
    
    def test_sandbox_resource_limit_edge_cases(self):
        """Test sandbox behavior with edge case resource limits."""
        # Test with zero limits (should disable limits)
        sandbox_zero = PluginSandbox(
            max_memory_mb=0,
            max_execution_time=0,
            max_cpu_time=0
        )
        
        config = sandbox_zero.get_sandbox_config()
        assert config['max_memory_mb'] == 0
        assert config['max_execution_time'] == 0
        assert config['max_cpu_time'] == 0
        
        # Test with very high limits
        sandbox_high = PluginSandbox(
            max_memory_mb=10000,
            max_execution_time=3600.0,
            max_cpu_time=1800.0
        )
        
        config = sandbox_high.get_sandbox_config()
        assert config['max_memory_mb'] == 10000
        assert config['max_execution_time'] == 3600.0
        assert config['max_cpu_time'] == 1800.0
    
    @patch('src.netstealth_analyzer.plugins.sandbox.HAS_RESOURCE', False)
    @pytest.mark.asyncio
    async def test_sandbox_without_resource_module(self):
        """Test sandbox behavior when resource module is not available."""
        sandbox = PluginSandbox(max_memory_mb=100, max_cpu_time=10.0)
        
        # Should not raise exceptions even without resource module
        old_limits = sandbox._setup_resource_limits()
        assert old_limits == {}
        
        sandbox._restore_resource_limits(old_limits)
        
        # Basic execution should still work
        plugin = MockPlugin()
        with sandbox.execute_sandboxed(plugin):
            pass
    
    @pytest.mark.asyncio
    async def test_plugin_metadata_sandboxed_flag_respected(self):
        """Test that plugin metadata sandboxed flag is respected."""
        sandbox = PluginSandbox()
        
        # Test with sandboxed plugin
        sandboxed_plugin = MockPlugin()  # sandboxed=True by default
        
        with patch.object(sandbox, '_setup_resource_limits') as mock_setup:
            with sandbox.execute_sandboxed(sandboxed_plugin):
                pass
            mock_setup.assert_called_once()
        
        # Test with non-sandboxed plugin
        non_sandboxed_plugin = NonSandboxedPlugin()  # sandboxed=False
        
        with patch.object(sandbox, '_setup_resource_limits') as mock_setup:
            with sandbox.execute_sandboxed(non_sandboxed_plugin):
                pass
            mock_setup.assert_not_called()
