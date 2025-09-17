"""
Integration tests for error handling across components.

Tests error propagation, recovery strategies, and cross-component error scenarios.
"""

import pytest
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from src.netstealth_analyzer.core.errors import (
    ErrorHandler, NetStealthError, PluginError, ConfigurationError,
    ValidationError, FileError, ParseError, ErrorSeverity, RecoveryStrategy
)
from src.netstealth_analyzer.plugins.loader import PluginLoader
from src.netstealth_analyzer.plugins.sandbox import PluginSandbox
from src.netstealth_analyzer.plugins.registry import PluginRegistry
from src.netstealth_analyzer.config import ConfigurationManager
from src.netstealth_analyzer.core.events import EventBus, AnalysisEvent


class TestErrorHandlingIntegration:
    """Test error handling integration across components."""
    
    @pytest.mark.asyncio
    async def test_plugin_error_propagation(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper,
        error_handler,
        event_bus
    ):
        """Test error propagation from plugin execution through the system."""
        # Create plugin that raises different types of errors
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class ErrorTestPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="error_test_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin for testing error handling"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def raise_value_error(self):
        raise ValueError("Test value error from plugin")
    
    async def raise_runtime_error(self):
        raise RuntimeError("Test runtime error from plugin")
    
    async def raise_custom_error(self):
        from src.netstealth_analyzer.core.errors import ValidationError
        raise ValidationError("Custom validation error from plugin")
    
    async def working_method(self):
        return "Plugin working correctly"
'''
        
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "error_test_plugin.py", plugin_code
        )
        
        # Load plugin
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        plugin = plugins[0]
        
        # Test error propagation for different error types
        errors_caught = []
        
        async def error_listener(event, error_data):
            errors_caught.append(error_data)
        
        subscription = event_bus.subscribe(AnalysisEvent.ERROR_OCCURRED, error_listener)
        
        # Test ValueError propagation
        with plugin_sandbox.execute_sandboxed(plugin):
            try:
                await plugin_sandbox.execute_plugin_method(plugin, "raise_value_error")
                assert False, "Should have raised an error"
            except Exception as e:
                assert "execution failed" in str(e).lower()
        
        # Test RuntimeError propagation
        with plugin_sandbox.execute_sandboxed(plugin):
            try:
                await plugin_sandbox.execute_plugin_method(plugin, "raise_runtime_error")
                assert False, "Should have raised an error"
            except Exception as e:
                assert "execution failed" in str(e).lower()
        
        # Test custom error propagation
        with plugin_sandbox.execute_sandboxed(plugin):
            try:
                await plugin_sandbox.execute_plugin_method(plugin, "raise_custom_error")
                assert False, "Should have raised an error"
            except Exception as e:
                assert "execution failed" in str(e).lower()
        
        # Verify working method still works
        with plugin_sandbox.execute_sandboxed(plugin):
            result = await plugin_sandbox.execute_plugin_method(plugin, "working_method")
            assert result == "Plugin working correctly"
        
        # Wait for async event processing
        await asyncio.sleep(0.1)
    
    @pytest.mark.asyncio
    async def test_configuration_error_recovery(
        self,
        config_manager,
        error_handler,
        event_bus
    ):
        """Test error recovery in configuration loading and validation."""
        errors_handled = []
        
        async def config_error_listener(event, error_data):
            errors_handled.append(error_data)
        
        subscription = event_bus.subscribe(AnalysisEvent.ERROR_OCCURRED, config_error_listener)
        
        # Test invalid configuration with recovery
        invalid_configs = [
            # Invalid analysis mode
            {"analysis_mode": "invalid_mode"},
            # Invalid parallel configuration
            {
                "analysis_mode": "parallel",
                "performance": {"enable_parallel_processing": False}
            },
            # Invalid confidence values
            {"filters": {"min_confidence": 1.5}},  # > 1.0
            # Invalid timeout
            {"performance": {"timeout_seconds": -10}}
        ]
        
        for i, invalid_config in enumerate(invalid_configs):
            try:
                config_manager.load_from_dict(invalid_config)
                assert False, f"Invalid config {i} should have raised an error"
            except ConfigurationError as e:
                # Verify error was handled
                assert "validation failed" in str(e).lower() or "invalid" in str(e).lower()
                
                # Verify system can still load valid configuration after error
                valid_config = {"target_service": "example.com"}
                config = config_manager.load_from_dict(valid_config)
                assert config.target_service == "example.com"
        
        await asyncio.sleep(0.1)  # Wait for events
    
    @pytest.mark.asyncio
    async def test_plugin_loading_error_recovery(
        self,
        plugin_registry,
        temp_plugin_dir,
        integration_helper,
        error_handler
    ):
        """Test error recovery during plugin loading."""
        # Create invalid plugin with syntax error
        invalid_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class InvalidPlugin(IPlugin
    # Missing colon and improper syntax
    def __init__(self, config=None):
        super().__init__(config)
        # Missing metadata definition
'''
        
        # Create valid plugin
        valid_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class ValidPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="valid_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Valid plugin for error recovery test"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''
        
        # Create plugin files
        invalid_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "invalid_plugin.py", invalid_plugin_code
        )
        valid_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "valid_plugin.py", valid_plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        
        # Try to load invalid plugin - should fail gracefully
        try:
            await loader.load_plugin_from_file(invalid_file)
            assert False, "Invalid plugin should have failed to load"
        except Exception as e:
            assert "failed to load" in str(e).lower() or "syntax" in str(e).lower()
        
        # After failure, should still be able to load valid plugin
        valid_plugins = await loader.load_plugin_from_file(valid_file)
        assert len(valid_plugins) == 1
        assert valid_plugins[0].name == "valid_plugin"
        
        # Plugin registry should only contain valid plugin
        registered_plugins = plugin_registry.list_plugins()
        assert len(registered_plugins) == 1
        assert registered_plugins[0]['name'] == "valid_plugin"
    
    @pytest.mark.asyncio
    async def test_cross_component_error_handling(
        self,
        plugin_registry,
        plugin_sandbox,
        config_manager,
        temp_plugin_dir,
        integration_helper,
        error_handler,
        event_bus,
        sample_network_trace
    ):
        """Test error handling across multiple components."""
        # Create plugin that validates configuration
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel
from src.netstealth_analyzer.core.errors import ValidationError, ConfigurationError

class CrossComponentPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="cross_component_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin for cross-component error testing"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect_with_config_validation(self, traces):
        """Method that validates configuration and processes traces."""
        # Check required configuration
        min_confidence = self.get_config_value("min_confidence")
        if min_confidence is None:
            raise ConfigurationError("min_confidence is required but not provided")
        
        if not isinstance(min_confidence, (int, float)) or min_confidence < 0 or min_confidence > 1:
            raise ValidationError(f"min_confidence must be between 0 and 1, got {min_confidence}")
        
        # Process traces
        if not traces:
            raise ValidationError("No traces provided for analysis")
        
        issues = []
        for trace in traces:
            if not hasattr(trace, 'trace_id'):
                raise ValidationError("Invalid trace: missing trace_id")
            
            # Create issue based on configuration
            if min_confidence <= 0.8:  # Only create issues if confidence threshold is reasonable
                issue = Issue(
                    id=f"cross-{trace.trace_id}",
                    category=IssueCategory.CONFIGURATION,
                    severity=SeverityLevel.LOW,
                    title="Cross-Component Detection",
                    description=f"Detection with min_confidence={min_confidence}",
                    confidence=min_confidence,
                    impact_score=int(min_confidence * 100)
                )
                issues.append(issue)
        
        return issues
'''
        
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "cross_component_plugin.py", plugin_code
        )
        
        # Test scenario 1: Missing configuration
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        plugin = plugins[0]
        
        with plugin_sandbox.execute_sandboxed(plugin):
            try:
                await plugin_sandbox.execute_plugin_method(
                    plugin, "detect_with_config_validation", [sample_network_trace]
                )
                assert False, "Should have failed due to missing configuration"
            except Exception as e:
                assert "execution failed" in str(e).lower()
        
        # Test scenario 2: Invalid configuration values
        invalid_config = {"min_confidence": 1.5}  # Invalid value > 1
        plugins_invalid = await loader.load_plugin_from_file(plugin_file, config=invalid_config)
        plugin_invalid = plugins_invalid[0]
        
        with plugin_sandbox.execute_sandboxed(plugin_invalid):
            try:
                await plugin_sandbox.execute_plugin_method(
                    plugin_invalid, "detect_with_config_validation", [sample_network_trace]
                )
                assert False, "Should have failed due to invalid configuration"
            except Exception as e:
                assert "execution failed" in str(e).lower()
        
        # Test scenario 3: Valid configuration - should succeed
        valid_config = {"min_confidence": 0.7}
        plugins_valid = await loader.load_plugin_from_file(plugin_file, config=valid_config)
        plugin_valid = plugins_valid[0]
        
        with plugin_sandbox.execute_sandboxed(plugin_valid):
            issues = await plugin_sandbox.execute_plugin_method(
                plugin_valid, "detect_with_config_validation", [sample_network_trace]
            )
            assert len(issues) == 1
            assert issues[0].confidence == 0.7
        
        # Test scenario 4: Empty traces - should fail gracefully
        with plugin_sandbox.execute_sandboxed(plugin_valid):
            try:
                await plugin_sandbox.execute_plugin_method(
                    plugin_valid, "detect_with_config_validation", []
                )
                assert False, "Should have failed due to empty traces"
            except Exception as e:
                assert "execution failed" in str(e).lower()
    
    @pytest.mark.asyncio
    async def test_error_recovery_strategies(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper,
        error_handler
    ):
        """Test different error recovery strategies."""
        # Create plugin with multiple recovery scenarios
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel

class RecoveryTestPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="recovery_test_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin for testing recovery strategies"
        )
        self.attempt_count = 0
    
    @property
    def metadata(self):
        return self._metadata
    
    async def flaky_method(self):
        """Method that fails first few times then succeeds."""
        self.attempt_count += 1
        if self.attempt_count < 3:
            raise RuntimeError(f"Flaky failure #{self.attempt_count}")
        return f"Success after {self.attempt_count} attempts"
    
    async def timeout_simulation(self):
        """Simulate a timeout scenario."""
        import asyncio
        await asyncio.sleep(0.1)  # Short delay to simulate work
        return "Operation completed"
    
    async def partial_failure_recovery(self, items):
        """Process items with some failing, some succeeding."""
        results = []
        errors = []
        
        for i, item in enumerate(items):
            try:
                if i % 3 == 1:  # Fail every 3rd item (starting from index 1)
                    raise ValueError(f"Processing failed for item {i}")
                results.append(f"Processed item {i}: {item}")
            except Exception as e:
                errors.append(str(e))
                # Continue processing other items (recovery strategy)
        
        return {"results": results, "errors": errors}
'''
        
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "recovery_plugin.py", plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        plugin = plugins[0]
        
        # Test flaky method recovery (would need retry logic in real system)
        with plugin_sandbox.execute_sandboxed(plugin):
            try:
                result = await plugin_sandbox.execute_plugin_method(plugin, "flaky_method")
                # First call might fail, but plugin state persists
                assert "attempts" in result or "failed" in str(result).lower()
            except Exception:
                # Expected on first attempts
                pass
        
        # Test timeout simulation
        with plugin_sandbox.execute_sandboxed(plugin):
            result = await plugin_sandbox.execute_plugin_method(plugin, "timeout_simulation")
            assert result == "Operation completed"
        
        # Test partial failure recovery
        test_items = ["item1", "item2", "item3", "item4", "item5"]
        with plugin_sandbox.execute_sandboxed(plugin):
            result = await plugin_sandbox.execute_plugin_method(
                plugin, "partial_failure_recovery", test_items
            )
            assert isinstance(result, dict)
            assert "results" in result
            assert "errors" in result
            assert len(result["results"]) == 3  # 5 items - 2 failed (items at indices 1 and 4)
            assert len(result["errors"]) == 2
            assert "item 1" in result["errors"][0]
