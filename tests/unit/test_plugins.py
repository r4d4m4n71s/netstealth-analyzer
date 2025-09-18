"""
Unit tests for the plugin system.

Tests the plugin base classes, registry, loader, and sandbox components
with full Python 3.13 compatibility validation.
"""

import asyncio
import pytest
from unittest.mock import Mock, AsyncMock, patch
from pathlib import Path
from typing import Dict, Any, List

from src.netstealth_analyzer.plugins.base import (
    IPlugin, IDetectorPlugin, IParserPlugin, IFormatterPlugin,
    PluginMetadata, PluginType, PluginStatus,
    PluginError, PluginLoadError, PluginInitializationError, PluginExecutionError
)
from src.netstealth_analyzer.plugins.registry import PluginRegistry, get_global_registry
from src.netstealth_analyzer.plugins.loader import PluginLoader
from src.netstealth_analyzer.plugins.sandbox import PluginSandbox
from src.netstealth_analyzer.detectors.base import DetectionContext, DetectionResult
from src.netstealth_analyzer.parsers.base import ParseResult
from src.netstealth_analyzer.models.enums import LogFormat


class TestPluginMetadata:
    """Test PluginMetadata class."""
    
    def test_plugin_metadata_creation(self, sample_plugin_metadata):
        """Test creating plugin metadata."""
        metadata = sample_plugin_metadata
        
        assert metadata.name == "test_plugin"
        assert metadata.version == "1.0.0"
        assert metadata.plugin_type.value == PluginType.DETECTOR.value
        assert metadata.description == "Test plugin for unit testing"
        assert metadata.author == "Test Author"
        assert metadata.python_version == "3.13+"
        assert metadata.sandboxed is True
        assert metadata.async_capable is True
    
    def test_plugin_metadata_to_dict(self, sample_plugin_metadata):
        """Test converting metadata to dictionary."""
        metadata = sample_plugin_metadata
        data = metadata.to_dict()
        
        assert isinstance(data, dict)
        assert data["name"] == "test_plugin"
        assert data["version"] == "1.0.0"
        assert data["plugin_type"] == "detector"
        assert data["python_version"] == "3.13+"
        assert data["sandboxed"] is True
        assert data["async_capable"] is True
        assert "created_at" in data


class MockDetectorPlugin(IDetectorPlugin):
    """Mock detector plugin for testing."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="mock_detector",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Mock detector for testing",
            author="Test Author",
            supported_categories=["proxy_leak"],
            async_capable=True,
            sandboxed=False  # Disable sandboxing for tests
        )
    
    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata
    
    async def detect(self, context: DetectionContext) -> DetectionResult:
        """Mock detection method."""
        return DetectionResult(
            detector_name="mock_detector",
            detector_version="1.0.0",
            execution_time_ms=10.0,
            issues_found=[],
            detection_rules_applied=[],
            statistics={"processed": 1},
            errors=[]
        )


class MockParserPlugin(IParserPlugin):
    """Mock parser plugin for testing."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="mock_parser",
            version="1.0.0",
            plugin_type=PluginType.PARSER,
            description="Mock parser for testing",
            author="Test Author",
            supported_formats=["json"],
            async_capable=True,
            sandboxed=False  # Disable sandboxing for tests
        )
    
    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata
    
    async def parse(self, file_path: str, **kwargs) -> ParseResult:
        """Mock parse method."""
        return ParseResult(
            format=LogFormat.HAR,
            source_file=file_path,
            metadata={},
            network_traces=[],
            statistics={"parsed": 1},
            errors=[]
        )
    
    def can_parse(self, file_path: str, content_sample: str) -> bool:
        """Mock can_parse method."""
        return file_path.endswith('.json')


class MockFormatterPlugin(IFormatterPlugin):
    """Mock formatter plugin for testing."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="mock_formatter",
            version="1.0.0",
            plugin_type=PluginType.FORMATTER,
            description="Mock formatter for testing",
            author="Test Author",
            async_capable=True,
            sandboxed=False  # Disable sandboxing for tests
        )
    
    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata
    
    def format(self, report) -> str:
        """Mock format method."""
        return "Mock formatted report"


class TestPluginBase:
    """Test plugin base classes."""
    
    @pytest.mark.asyncio
    async def test_plugin_initialization(self):
        """Test plugin initialization."""
        plugin = MockDetectorPlugin()
        
        assert plugin.status == PluginStatus.UNLOADED
        assert not plugin.is_initialized
        
        await plugin.initialize()
        
        assert plugin.status == PluginStatus.LOADED
        assert plugin.is_initialized
    
    @pytest.mark.asyncio
    async def test_plugin_cleanup(self):
        """Test plugin cleanup."""
        plugin = MockDetectorPlugin()
        await plugin.initialize()
        
        assert plugin.is_initialized
        
        await plugin.cleanup()
        
        assert plugin.status == PluginStatus.UNLOADED
        assert not plugin.is_initialized
    
    def test_plugin_properties(self):
        """Test plugin properties."""
        plugin = MockDetectorPlugin()
        
        assert plugin.name == "mock_detector"
        assert plugin.version == "1.0.0"
        assert plugin.plugin_type == PluginType.DETECTOR
    
    def test_plugin_config_validation(self):
        """Test plugin configuration validation."""
        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            config_schema={
                "threshold": {"type": float, "required": True},
                "enabled": {"type": bool, "required": False}
            }
        )
        
        plugin = MockDetectorPlugin()
        plugin._metadata = metadata
        
        # Valid config
        assert plugin.validate_config({"threshold": 0.7, "enabled": True})
        assert plugin.validate_config({"threshold": 0.5})  # enabled is optional
        
        # Invalid config - missing required field
        assert not plugin.validate_config({"enabled": True})
        
        # Invalid config - wrong type
        assert not plugin.validate_config({"threshold": "invalid"})
    
    def test_plugin_config_values(self):
        """Test getting configuration values."""
        config = {"threshold": 0.8, "custom": "value"}
        plugin = MockDetectorPlugin(config)
        
        assert plugin.get_config_value("threshold") == 0.8
        assert plugin.get_config_value("custom") == "value"
        assert plugin.get_config_value("missing", "default") == "default"
    
    @pytest.mark.asyncio
    async def test_detector_plugin_interface(self):
        """Test detector plugin interface."""
        plugin = MockDetectorPlugin()
        context = Mock(spec=DetectionContext)
        
        result = await plugin.detect(context)
        
        assert isinstance(result, DetectionResult)
        assert result.statistics["processed"] == 1
    
    @pytest.mark.asyncio
    async def test_parser_plugin_interface(self):
        """Test parser plugin interface."""
        plugin = MockParserPlugin()
        
        # Test parsing
        result = await plugin.parse("test.json")
        assert isinstance(result, ParseResult)
        assert result.statistics["parsed"] == 1
        
        # Test can_parse
        assert plugin.can_parse("test.json", "")
        assert not plugin.can_parse("test.har", "")
    
    def test_formatter_plugin_interface(self):
        """Test formatter plugin interface."""
        plugin = MockFormatterPlugin()
        report = Mock()
        
        result = plugin.format(report)
        assert result == "Mock formatted report"


class TestPluginRegistry:
    """Test PluginRegistry class."""
    
    @pytest.mark.asyncio
    async def test_plugin_registration(self, plugin_registry):
        """Test plugin registration."""
        plugin = MockDetectorPlugin()
        
        await plugin_registry.register_plugin(plugin, auto_initialize=False)
        
        assert plugin_registry.plugin_count == 1
        assert plugin_registry.get_plugin("mock_detector") == plugin
    
    @pytest.mark.asyncio
    async def test_plugin_registration_with_initialization(self, plugin_registry):
        """Test plugin registration with auto-initialization."""
        plugin = MockDetectorPlugin()
        
        await plugin_registry.register_plugin(plugin, auto_initialize=True)
        
        assert plugin.is_initialized
        assert plugin in plugin_registry.loaded_plugins
    
    @pytest.mark.asyncio
    async def test_plugin_unregistration(self, plugin_registry):
        """Test plugin unregistration."""
        plugin = MockDetectorPlugin()
        await plugin_registry.register_plugin(plugin)
        
        assert plugin_registry.plugin_count == 1
        
        await plugin_registry.unregister_plugin("mock_detector")
        
        assert plugin_registry.plugin_count == 0
        assert plugin_registry.get_plugin("mock_detector") is None
    
    @pytest.mark.asyncio
    async def test_plugin_initialization(self, plugin_registry):
        """Test plugin initialization."""
        plugin = MockDetectorPlugin()
        await plugin_registry.register_plugin(plugin, auto_initialize=False)
        
        assert not plugin.is_initialized
        
        await plugin_registry.initialize_plugin("mock_detector")
        
        assert plugin.is_initialized
    
    @pytest.mark.asyncio
    async def test_initialize_all_plugins(self, plugin_registry):
        """Test initializing all plugins."""
        plugin1 = MockDetectorPlugin()
        plugin2 = MockParserPlugin()
        
        await plugin_registry.register_plugin(plugin1, auto_initialize=False)
        await plugin_registry.register_plugin(plugin2, auto_initialize=False)
        
        await plugin_registry.initialize_all_plugins()
        
        assert plugin1.is_initialized
        assert plugin2.is_initialized
    
    @pytest.mark.asyncio
    async def test_cleanup_all_plugins(self, plugin_registry):
        """Test cleaning up all plugins."""
        plugin1 = MockDetectorPlugin()
        plugin2 = MockParserPlugin()
        
        await plugin_registry.register_plugin(plugin1)
        await plugin_registry.register_plugin(plugin2)
        
        await plugin_registry.cleanup_all_plugins()
        
        assert not plugin1.is_initialized
        assert not plugin2.is_initialized
    
    def test_get_plugins_by_type(self, plugin_registry):
        """Test getting plugins by type."""
        detector = MockDetectorPlugin()
        parser = MockParserPlugin()
        formatter = MockFormatterPlugin()
        
        asyncio.run(plugin_registry.register_plugin(detector, auto_initialize=False))
        asyncio.run(plugin_registry.register_plugin(parser, auto_initialize=False))
        asyncio.run(plugin_registry.register_plugin(formatter, auto_initialize=False))
        
        detectors = plugin_registry.get_detector_plugins()
        parsers = plugin_registry.get_parser_plugins()
        formatters = plugin_registry.get_formatter_plugins()
        
        assert len(detectors) == 1
        assert len(parsers) == 1
        assert len(formatters) == 1
        assert detectors[0] == detector
        assert parsers[0] == parser
        assert formatters[0] == formatter
    
    def test_find_plugins_by_capability(self, plugin_registry):
        """Test finding plugins by capability."""
        detector = MockDetectorPlugin()
        parser = MockParserPlugin()
        
        asyncio.run(plugin_registry.register_plugin(detector, auto_initialize=False))
        asyncio.run(plugin_registry.register_plugin(parser, auto_initialize=False))
        
        # Find by supported categories
        proxy_plugins = plugin_registry.find_plugins_by_capability("supported_categories", "proxy_leak")
        assert len(proxy_plugins) == 1
        assert proxy_plugins[0] == detector
        
        # Find by supported formats
        json_plugins = plugin_registry.find_plugins_by_capability("supported_formats", "json")
        assert len(json_plugins) == 1
        assert json_plugins[0] == parser
    
    def test_registry_stats(self, plugin_registry):
        """Test registry statistics."""
        detector = MockDetectorPlugin()
        parser = MockParserPlugin()
        
        asyncio.run(plugin_registry.register_plugin(detector))
        asyncio.run(plugin_registry.register_plugin(parser))
        
        stats = plugin_registry.get_registry_stats()
        
        assert stats["total_plugins"] == 2
        assert stats["loaded_plugins"] == 2
        assert stats["plugins_by_type"]["detector"] == 1
        assert stats["plugins_by_type"]["parser"] == 1
    
    def test_list_plugins(self, plugin_registry):
        """Test listing plugins."""
        detector = MockDetectorPlugin()
        asyncio.run(plugin_registry.register_plugin(detector))
        
        plugins = plugin_registry.list_plugins()
        
        assert len(plugins) == 1
        plugin_info = plugins[0]
        assert plugin_info["name"] == "mock_detector"
        assert plugin_info["version"] == "1.0.0"
        assert plugin_info["type"] == "detector"
        assert plugin_info["initialized"] is True


class TestPluginLoader:
    """Test PluginLoader class."""
    
    def test_loader_creation(self, plugin_registry):
        """Test creating plugin loader."""
        loader = PluginLoader(plugin_registry)
        
        assert loader.registry == plugin_registry
        assert len(loader.get_loaded_modules()) == 0
    
    @pytest.mark.asyncio
    async def test_load_plugin_class(self, plugin_registry):
        """Test loading plugin from class."""
        loader = PluginLoader(plugin_registry)
        
        plugin = await loader.load_plugin_class(MockDetectorPlugin, auto_register=False)
        
        assert isinstance(plugin, MockDetectorPlugin)
        assert plugin.name == "mock_detector"
    
    @pytest.mark.asyncio
    async def test_load_plugin_class_with_registration(self, plugin_registry):
        """Test loading plugin class with auto-registration."""
        loader = PluginLoader(plugin_registry)
        
        plugin = await loader.load_plugin_class(MockDetectorPlugin, auto_register=True)
        
        assert plugin_registry.get_plugin("mock_detector") == plugin
    
    def test_loader_stats(self, plugin_registry):
        """Test loader statistics."""
        loader = PluginLoader(plugin_registry)
        stats = loader.get_loader_stats()
        
        assert "loaded_modules" in stats
        assert "module_names" in stats
        assert stats["loaded_modules"] == 0


class TestPluginSandbox:
    """Test PluginSandbox class."""
    
    def test_sandbox_creation(self):
        """Test creating plugin sandbox."""
        sandbox = PluginSandbox(
            max_memory_mb=50,
            max_execution_time=10.0,
            max_cpu_time=5.0
        )
        
        config = sandbox.get_sandbox_config()
        assert config["max_memory_mb"] == 50
        assert config["max_execution_time"] == 10.0
        assert config["max_cpu_time"] == 5.0
        assert config["allow_network"] is True
        assert config["allow_file_access"] is True
    
    @pytest.mark.asyncio
    async def test_execute_plugin_method(self):
        """Test executing plugin method in sandbox."""
        sandbox = PluginSandbox()
        plugin = MockDetectorPlugin()
        plugin._metadata.sandboxed = False  # Disable sandboxing for test
        
        # Test sync method
        result = await sandbox.execute_plugin_method(plugin, "get_config_value", "test", "default")
        assert result == "default"
        
        # Test async method
        await plugin.initialize()
        context = Mock(spec=DetectionContext)
        result = await sandbox.execute_plugin_method(plugin, "detect", context)
        assert isinstance(result, DetectionResult)
    
    @pytest.mark.asyncio
    async def test_execute_plugin_method_errors(self):
        """Test error handling in plugin method execution."""
        sandbox = PluginSandbox()
        plugin = MockDetectorPlugin()
        
        # Test non-existent method
        with pytest.raises(PluginExecutionError):
            await sandbox.execute_plugin_method(plugin, "non_existent_method")
        
        # Test non-callable attribute
        plugin.non_callable = "not a method"
        with pytest.raises(PluginExecutionError):
            await sandbox.execute_plugin_method(plugin, "non_callable")
    
    def test_sandboxed_execution_context(self):
        """Test sandboxed execution context manager."""
        sandbox = PluginSandbox()
        plugin = MockDetectorPlugin()
        plugin._metadata.sandboxed = False  # Disable actual sandboxing
        
        with sandbox.execute_sandboxed(plugin):
            # Should execute without issues
            pass
    
    def test_sandbox_with_non_sandboxed_plugin(self):
        """Test sandbox with plugin that doesn't require sandboxing."""
        sandbox = PluginSandbox()
        plugin = MockDetectorPlugin()
        plugin._metadata.sandboxed = False
        
        # Should pass through without sandboxing
        with sandbox.execute_sandboxed(plugin):
            pass


class TestPluginErrors:
    """Test plugin error classes."""
    
    def test_plugin_error(self):
        """Test base PluginError."""
        error = PluginError("Test error", "test_plugin")
        
        assert str(error) == "Test error"
        assert error.plugin_name == "test_plugin"
        assert error.cause is None
    
    def test_plugin_load_error(self):
        """Test PluginLoadError."""
        cause = ValueError("Invalid plugin")
        error = PluginLoadError("Failed to load", "test_plugin", cause)
        
        assert isinstance(error, PluginError)
        assert error.cause == cause
    
    def test_plugin_initialization_error(self):
        """Test PluginInitializationError."""
        error = PluginInitializationError("Init failed", "test_plugin")
        
        assert isinstance(error, PluginError)
        assert error.plugin_name == "test_plugin"
    
    def test_plugin_execution_error(self):
        """Test PluginExecutionError."""
        error = PluginExecutionError("Execution failed", "test_plugin")
        
        assert isinstance(error, PluginError)
        assert error.plugin_name == "test_plugin"


class TestGlobalRegistry:
    """Test global registry functions."""
    
    def test_get_global_registry(self):
        """Test getting global registry."""
        registry1 = get_global_registry()
        registry2 = get_global_registry()
        
        assert registry1 is registry2
        assert isinstance(registry1, PluginRegistry)
    
    def test_reset_global_registry(self):
        """Test resetting global registry."""
        from src.netstealth_analyzer.plugins.registry import reset_global_registry
        
        registry1 = get_global_registry()
        reset_global_registry()
        registry2 = get_global_registry()
        
        assert registry1 is not registry2
