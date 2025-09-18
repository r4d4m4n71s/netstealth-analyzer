"""
Unit tests for NetStealth Analyzer plugin registry.

Tests the PluginRegistry class for plugin management, registration,
initialization, dependency resolution, and lifecycle management.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any, List, Optional

from src.netstealth_analyzer.plugins.registry import (
    PluginRegistry,
    get_global_registry,
    reset_global_registry
)
from src.netstealth_analyzer.plugins.base import (
    IPlugin,
    IDetectorPlugin,
    IParserPlugin,
    IFormatterPlugin,
    PluginMetadata,
    PluginType,
    PluginStatus,
    PluginError,
    PluginLoadError,
    PluginInitializationError
)


class MockPlugin(IPlugin):
    """Mock plugin for testing."""
    
    def __init__(self, name: str = "test_plugin", version: str = "1.0.0", 
                 plugin_type: PluginType = PluginType.DETECTOR,
                 dependencies: List[str] = None, config: Optional[Dict[str, Any]] = None):
        # Call parent constructor first
        super().__init__(config)
        
        # Create metadata - this is what the base class uses for name/version/type
        self._metadata = PluginMetadata(
            name=name,
            version=version,
            plugin_type=plugin_type,
            dependencies=dependencies or []
        )
    
    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata
    
    async def _initialize_impl(self) -> None:
        """Plugin-specific initialization implementation."""
        # Custom initialization logic can go here
        pass
    
    async def _cleanup_impl(self) -> None:
        """Plugin-specific cleanup implementation."""
        # Custom cleanup logic can go here
        pass
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return True


class MockDetectorPlugin(MockPlugin, IDetectorPlugin):
    """Mock detector plugin for testing."""
    
    def __init__(self, name: str = "detector_plugin", **kwargs):
        super().__init__(name=name, plugin_type=PluginType.DETECTOR, **kwargs)
    
    async def detect(self, data: Any) -> List[Any]:
        return []


class MockParserPlugin(MockPlugin, IParserPlugin):
    """Mock parser plugin for testing."""
    
    def __init__(self, name: str = "parser_plugin", **kwargs):
        super().__init__(name=name, plugin_type=PluginType.PARSER, **kwargs)
    
    async def parse(self, file_path: str, **kwargs) -> Any:
        return {"file_path": file_path}
    
    def can_parse(self, file_path: str, content_sample: str) -> bool:
        return True


class MockFormatterPlugin(MockPlugin, IFormatterPlugin):
    """Mock formatter plugin for testing."""
    
    def __init__(self, name: str = "formatter_plugin", **kwargs):
        super().__init__(name=name, plugin_type=PluginType.FORMATTER, **kwargs)
    
    def format(self, report: Any) -> str:
        return str(report)


class TestPluginRegistry:
    """Test PluginRegistry class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.registry = PluginRegistry()
        # Clear any existing plugins to ensure test isolation
        self.registry._plugins.clear()
        self.registry._plugin_classes.clear()
    
    def test_registry_initialization(self):
        """Test registry initialization."""
        assert self.registry.plugin_count == 0
        assert len(self.registry.loaded_plugins) == 0
        assert len(self.registry.active_plugins) == 0
        assert len(self.registry.list_plugins()) == 0
    
    def test_register_plugin_class_valid(self):
        """Test registering a valid plugin class."""
        self.registry.register_plugin_class(MockPlugin)
        
        # Should not raise an exception
        assert True
    
    def test_register_plugin_class_invalid(self):
        """Test registering an invalid plugin class."""
        class InvalidPlugin:
            pass
        
        with pytest.raises(PluginError, match="must inherit from IPlugin"):
            self.registry.register_plugin_class(InvalidPlugin)
    
    def test_register_plugin_class_duplicate(self):
        """Test registering duplicate plugin class."""
        self.registry.register_plugin_class(MockPlugin)
        
        with pytest.raises(PluginError, match="already registered"):
            self.registry.register_plugin_class(MockPlugin)
    
    def test_register_plugin_class_metadata_error(self):
        """Test registering plugin class with metadata error."""
        class BrokenPlugin(IPlugin):
            def __init__(self):
                raise ValueError("Broken plugin")
        
        with pytest.raises(PluginError, match="Failed to get metadata"):
            self.registry.register_plugin_class(BrokenPlugin)
    
    @pytest.mark.asyncio
    async def test_register_plugin_success(self):
        """Test successful plugin registration."""
        plugin = MockPlugin(name="test_plugin", version="1.0.0")
        
        await self.registry.register_plugin(plugin, auto_initialize=False)
        
        assert self.registry.plugin_count == 1
        assert self.registry.get_plugin("test_plugin") == plugin
        assert plugin in self.registry.get_plugins_by_type(PluginType.DETECTOR)
    
    @pytest.mark.asyncio
    async def test_register_plugin_duplicate(self):
        """Test registering duplicate plugin."""
        plugin1 = MockPlugin(name="test_plugin", version="1.0.0")
        plugin2 = MockPlugin(name="test_plugin", version="2.0.0")
        
        await self.registry.register_plugin(plugin1, auto_initialize=False)
        
        with pytest.raises(PluginError, match="already registered"):
            await self.registry.register_plugin(plugin2, auto_initialize=False)
    
    @pytest.mark.asyncio
    async def test_register_plugin_with_auto_initialize(self):
        """Test plugin registration with auto-initialization."""
        plugin = MockPlugin(name="test_plugin", version="1.0.0")
        
        await self.registry.register_plugin(plugin, auto_initialize=True)
        
        assert plugin.is_initialized
        assert plugin.status == PluginStatus.LOADED
    
    @pytest.mark.asyncio
    async def test_register_plugin_validation_failure(self):
        """Test plugin registration with validation failure."""
        plugin = MockPlugin(name="", version="")  # Invalid name and version
        
        with pytest.raises(PluginError, match="failed validation"):
            await self.registry.register_plugin(plugin, auto_initialize=False)
    
    @pytest.mark.asyncio
    async def test_unregister_plugin_success(self):
        """Test successful plugin unregistration."""
        plugin = MockPlugin(name="test_plugin", version="1.0.0")
        await self.registry.register_plugin(plugin, auto_initialize=True)
        
        assert self.registry.plugin_count == 1
        assert plugin.is_initialized
        
        await self.registry.unregister_plugin("test_plugin")
        
        assert self.registry.plugin_count == 0
        assert self.registry.get_plugin("test_plugin") is None
        assert not plugin.is_initialized
    
    @pytest.mark.asyncio
    async def test_unregister_plugin_not_found(self):
        """Test unregistering non-existent plugin."""
        with pytest.raises(PluginError, match="not registered"):
            await self.registry.unregister_plugin("nonexistent_plugin")
    
    @pytest.mark.asyncio
    async def test_initialize_plugin_success(self):
        """Test successful plugin initialization."""
        plugin = MockPlugin(name="test_plugin", version="1.0.0")
        await self.registry.register_plugin(plugin, auto_initialize=False)
        
        assert not plugin.is_initialized
        
        await self.registry.initialize_plugin("test_plugin")
        
        assert plugin.is_initialized
        assert plugin.status == PluginStatus.LOADED
    
    @pytest.mark.asyncio
    async def test_initialize_plugin_not_found(self):
        """Test initializing non-existent plugin."""
        with pytest.raises(PluginInitializationError, match="not registered"):
            await self.registry.initialize_plugin("nonexistent_plugin")
    
    @pytest.mark.asyncio
    async def test_initialize_plugin_already_initialized(self):
        """Test initializing already initialized plugin."""
        plugin = MockPlugin(name="test_plugin", version="1.0.0")
        await self.registry.register_plugin(plugin, auto_initialize=True)
        
        assert plugin.is_initialized
        
        # Should not raise an error, just log a warning
        await self.registry.initialize_plugin("test_plugin")
        assert plugin.is_initialized
    
    @pytest.mark.asyncio
    async def test_initialize_plugin_with_dependencies(self):
        """Test plugin initialization with dependencies."""
        # Create dependency plugin
        dep_plugin = MockPlugin(name="dependency", version="1.0.0")
        await self.registry.register_plugin(dep_plugin, auto_initialize=False)
        
        # Create plugin with dependency
        plugin = MockPlugin(name="test_plugin", version="1.0.0", dependencies=["dependency"])
        await self.registry.register_plugin(plugin, auto_initialize=False)
        
        # Initialize main plugin (should initialize dependency first)
        await self.registry.initialize_plugin("test_plugin")
        
        assert dep_plugin.is_initialized
        assert plugin.is_initialized
    
    @pytest.mark.asyncio
    async def test_initialize_plugin_missing_dependency(self):
        """Test plugin initialization with missing dependency."""
        plugin = MockPlugin(name="test_plugin", version="1.0.0", dependencies=["missing_dep"])
        await self.registry.register_plugin(plugin, auto_initialize=False)
        
        with pytest.raises(PluginInitializationError, match="Dependency 'missing_dep' not found"):
            await self.registry.initialize_plugin("test_plugin")
    
    @pytest.mark.asyncio
    async def test_initialize_plugin_initialization_error(self):
        """Test plugin initialization with error."""
        plugin = MockPlugin(name="test_plugin", version="1.0.0")
        plugin.initialize = AsyncMock(side_effect=Exception("Init failed"))
        
        await self.registry.register_plugin(plugin, auto_initialize=False)
        
        with pytest.raises(PluginInitializationError, match="Failed to initialize"):
            await self.registry.initialize_plugin("test_plugin")
    
    @pytest.mark.asyncio
    async def test_initialize_all_plugins(self):
        """Test initializing all plugins."""
        plugin1 = MockPlugin(name="plugin1", version="1.0.0")
        plugin2 = MockPlugin(name="plugin2", version="1.0.0")
        plugin3 = MockPlugin(name="plugin3", version="1.0.0", dependencies=["plugin1"])
        
        await self.registry.register_plugin(plugin1, auto_initialize=False)
        await self.registry.register_plugin(plugin2, auto_initialize=False)
        await self.registry.register_plugin(plugin3, auto_initialize=False)
        
        await self.registry.initialize_all_plugins()
        
        assert plugin1.is_initialized
        assert plugin2.is_initialized
        assert plugin3.is_initialized
    
    @pytest.mark.asyncio
    async def test_initialize_all_plugins_with_error(self):
        """Test initializing all plugins with one failing."""
        plugin1 = MockPlugin(name="plugin1", version="1.0.0")
        plugin2 = MockPlugin(name="plugin2", version="1.0.0")
        plugin2.initialize = AsyncMock(side_effect=Exception("Init failed"))
        
        await self.registry.register_plugin(plugin1, auto_initialize=False)
        await self.registry.register_plugin(plugin2, auto_initialize=False)
        
        # Should not raise exception, just log error and continue
        await self.registry.initialize_all_plugins()
        
        assert plugin1.is_initialized
        assert not plugin2.is_initialized
    
    @pytest.mark.asyncio
    async def test_cleanup_all_plugins(self):
        """Test cleaning up all plugins."""
        plugin1 = MockPlugin(name="plugin1", version="1.0.0")
        plugin2 = MockPlugin(name="plugin2", version="1.0.0")
        
        await self.registry.register_plugin(plugin1, auto_initialize=True)
        await self.registry.register_plugin(plugin2, auto_initialize=True)
        
        assert plugin1.is_initialized
        assert plugin2.is_initialized
        
        await self.registry.cleanup_all_plugins()
        
        assert not plugin1.is_initialized
        assert not plugin2.is_initialized
    
    @pytest.mark.asyncio
    async def test_cleanup_all_plugins_with_error(self):
        """Test cleaning up all plugins with one failing."""
        plugin1 = MockPlugin(name="plugin1", version="1.0.0")
        plugin2 = MockPlugin(name="plugin2", version="1.0.0")
        plugin2.cleanup = AsyncMock(side_effect=Exception("Cleanup failed"))
        
        await self.registry.register_plugin(plugin1, auto_initialize=True)
        await self.registry.register_plugin(plugin2, auto_initialize=True)
        
        # Should not raise exception, just log error and continue
        await self.registry.cleanup_all_plugins()
        
        assert not plugin1.is_initialized
        # plugin2 cleanup failed, but should still be marked as not initialized
    
    def test_get_plugins_by_type(self):
        """Test getting plugins by type."""
        detector = MockDetectorPlugin("detector1")
        parser = MockParserPlugin("parser1")
        formatter = MockFormatterPlugin("formatter1")
        
        asyncio.run(self.registry.register_plugin(detector, auto_initialize=False))
        asyncio.run(self.registry.register_plugin(parser, auto_initialize=False))
        asyncio.run(self.registry.register_plugin(formatter, auto_initialize=False))
        
        detectors = self.registry.get_plugins_by_type(PluginType.DETECTOR)
        parsers = self.registry.get_plugins_by_type(PluginType.PARSER)
        formatters = self.registry.get_plugins_by_type(PluginType.FORMATTER)
        
        assert len(detectors) == 1
        assert len(parsers) == 1
        assert len(formatters) == 1
        assert detector in detectors
        assert parser in parsers
        assert formatter in formatters
    
    def test_get_typed_plugins(self):
        """Test getting plugins by specific interface types."""
        detector = MockDetectorPlugin("detector1")
        parser = MockParserPlugin("parser1")
        formatter = MockFormatterPlugin("formatter1")
        
        asyncio.run(self.registry.register_plugin(detector, auto_initialize=False))
        asyncio.run(self.registry.register_plugin(parser, auto_initialize=False))
        asyncio.run(self.registry.register_plugin(formatter, auto_initialize=False))
        
        detector_plugins = self.registry.get_detector_plugins()
        parser_plugins = self.registry.get_parser_plugins()
        formatter_plugins = self.registry.get_formatter_plugins()
        
        assert len(detector_plugins) == 1
        assert len(parser_plugins) == 1
        assert len(formatter_plugins) == 1
        assert isinstance(detector_plugins[0], IDetectorPlugin)
        assert isinstance(parser_plugins[0], IParserPlugin)
        assert isinstance(formatter_plugins[0], IFormatterPlugin)
    
    def test_list_plugins(self):
        """Test listing all plugins with metadata."""
        plugin = MockPlugin(name="test_plugin", version="1.0.0")
        asyncio.run(self.registry.register_plugin(plugin, auto_initialize=False))
        
        plugin_list = self.registry.list_plugins()
        
        assert len(plugin_list) == 1
        plugin_info = plugin_list[0]
        assert plugin_info['name'] == "test_plugin"
        assert plugin_info['version'] == "1.0.0"
        assert plugin_info['type'] == PluginType.DETECTOR.value
        assert plugin_info['status'] == PluginStatus.UNLOADED.value
        assert plugin_info['initialized'] is False
        assert 'metadata' in plugin_info
    
    def test_find_plugins_by_capability(self):
        """Test finding plugins by capability."""
        # Create plugin with custom metadata
        plugin = MockPlugin("test_plugin", "1.0.0")
        plugin._metadata.supported_formats = ["json", "xml"]
        
        asyncio.run(self.registry.register_plugin(plugin, auto_initialize=False))
        
        # Find by capability existence
        plugins = self.registry.find_plugins_by_capability("supported_formats")
        assert len(plugins) == 1
        assert plugin in plugins
        
        # Find by specific capability value
        plugins = self.registry.find_plugins_by_capability("supported_formats", "json")
        assert len(plugins) == 1
        assert plugin in plugins
        
        # Find by non-existent capability value
        plugins = self.registry.find_plugins_by_capability("supported_formats", "yaml")
        assert len(plugins) == 0
        
        # Find by non-existent capability
        plugins = self.registry.find_plugins_by_capability("nonexistent_capability")
        assert len(plugins) == 0
    
    @pytest.mark.asyncio
    async def test_create_plugin_from_class(self):
        """Test creating plugin instance from registered class."""
        self.registry.register_plugin_class(MockPlugin)
        
        plugin = await self.registry.create_plugin_from_class("test_plugin")
        
        assert isinstance(plugin, MockPlugin)
        # The plugin name comes from the metadata, which uses the default "test_plugin"
        assert plugin.name == "test_plugin"
        assert plugin.version == "1.0.0"
    
    @pytest.mark.asyncio
    async def test_create_plugin_from_class_not_found(self):
        """Test creating plugin from non-existent class."""
        with pytest.raises(PluginError, match="not registered"):
            await self.registry.create_plugin_from_class("nonexistent_plugin")
    
    @pytest.mark.asyncio
    async def test_create_plugin_from_class_with_config(self):
        """Test creating plugin from class with configuration."""
        # Create a custom plugin class that accepts config in constructor
        class ConfigurablePlugin(MockPlugin):
            def __init__(self, config=None):
                super().__init__(config=config)
        
        self.registry.register_plugin_class(ConfigurablePlugin)
        config = {"setting": "value"}
        
        plugin = await self.registry.create_plugin_from_class("test_plugin", config)
        
        assert plugin.config == config
    
    @pytest.mark.asyncio
    async def test_create_plugin_from_class_creation_error(self):
        """Test plugin creation error."""
        class BrokenPlugin(MockPlugin):
            def __init__(self, config=None):
                # Call parent constructor first to get metadata, then fail
                super().__init__()
                raise ValueError("Creation failed")
        
        # This should fail during registration since we create a temp instance
        with pytest.raises(PluginError, match="Failed to get metadata"):
            self.registry.register_plugin_class(BrokenPlugin)
    
    def test_validate_plugin_valid(self):
        """Test plugin validation with valid plugin."""
        plugin = MockPlugin("test_plugin", "1.0.0")
        assert self.registry._validate_plugin(plugin) is True
    
    def test_validate_plugin_invalid_name(self):
        """Test plugin validation with invalid name."""
        plugin = MockPlugin("", "1.0.0")
        assert self.registry._validate_plugin(plugin) is False
    
    def test_validate_plugin_invalid_version(self):
        """Test plugin validation with invalid version."""
        plugin = MockPlugin("test_plugin", "")
        assert self.registry._validate_plugin(plugin) is False
    
    def test_validate_plugin_invalid_type(self):
        """Test plugin validation with invalid type."""
        plugin = MockPlugin("test_plugin", "1.0.0")
        plugin._metadata.plugin_type = "invalid_type"
        assert self.registry._validate_plugin(plugin) is False
    
    def test_validate_plugin_config_validation_failure(self):
        """Test plugin validation with config validation failure."""
        plugin = MockPlugin(name="test_plugin", version="1.0.0", config={"test": "value"})
        plugin.validate_config = Mock(return_value=False)
        assert self.registry._validate_plugin(plugin) is False
    
    def test_validate_plugin_exception(self):
        """Test plugin validation with exception."""
        plugin = MockPlugin("test_plugin", "1.0.0")
        # Mock the metadata property to raise an exception
        with patch.object(type(plugin), 'metadata', new_callable=lambda: Mock(side_effect=Exception("Metadata error"))):
            assert self.registry._validate_plugin(plugin) is False
    
    def test_resolve_initialization_order_simple(self):
        """Test dependency resolution with simple dependencies."""
        plugin1 = MockPlugin("plugin1", "1.0.0")
        plugin2 = MockPlugin("plugin2", "1.0.0", dependencies=["plugin1"])
        
        asyncio.run(self.registry.register_plugin(plugin1, auto_initialize=False))
        asyncio.run(self.registry.register_plugin(plugin2, auto_initialize=False))
        
        order = self.registry._resolve_initialization_order()
        
        assert order.index("plugin1") < order.index("plugin2")
    
    def test_resolve_initialization_order_complex(self):
        """Test dependency resolution with complex dependencies."""
        plugin1 = MockPlugin("plugin1", "1.0.0")
        plugin2 = MockPlugin("plugin2", "1.0.0", dependencies=["plugin1"])
        plugin3 = MockPlugin("plugin3", "1.0.0", dependencies=["plugin1", "plugin2"])
        
        asyncio.run(self.registry.register_plugin(plugin1, auto_initialize=False))
        asyncio.run(self.registry.register_plugin(plugin2, auto_initialize=False))
        asyncio.run(self.registry.register_plugin(plugin3, auto_initialize=False))
        
        order = self.registry._resolve_initialization_order()
        
        assert order.index("plugin1") < order.index("plugin2")
        assert order.index("plugin2") < order.index("plugin3")
    
    def test_resolve_initialization_order_circular_dependency(self):
        """Test dependency resolution with circular dependency."""
        plugin1 = MockPlugin("plugin1", "1.0.0", dependencies=["plugin2"])
        plugin2 = MockPlugin("plugin2", "1.0.0", dependencies=["plugin1"])
        
        asyncio.run(self.registry.register_plugin(plugin1, auto_initialize=False))
        asyncio.run(self.registry.register_plugin(plugin2, auto_initialize=False))
        
        with pytest.raises(PluginError, match="Circular dependency detected"):
            self.registry._resolve_initialization_order()
    
    def test_get_registry_stats(self):
        """Test getting registry statistics."""
        detector = MockDetectorPlugin("detector1")
        parser = MockParserPlugin("parser1")
        
        asyncio.run(self.registry.register_plugin(detector, auto_initialize=True))
        asyncio.run(self.registry.register_plugin(parser, auto_initialize=False))
        
        stats = self.registry.get_registry_stats()
        
        assert stats['total_plugins'] == 2
        assert stats['loaded_plugins'] == 1
        assert stats['active_plugins'] == 0  # No plugins are active (different from loaded)
        assert stats['plugins_by_type'][PluginType.DETECTOR.value] == 1
        assert stats['plugins_by_type'][PluginType.PARSER.value] == 1
        assert len(stats['initialization_order']) == 1
        assert "detector1" in stats['initialization_order']
    
    def test_loaded_plugins_property(self):
        """Test loaded_plugins property."""
        plugin1 = MockPlugin("plugin1", "1.0.0")
        plugin2 = MockPlugin("plugin2", "1.0.0")
        
        asyncio.run(self.registry.register_plugin(plugin1, auto_initialize=True))
        asyncio.run(self.registry.register_plugin(plugin2, auto_initialize=False))
        
        loaded = self.registry.loaded_plugins
        assert len(loaded) == 1
        assert plugin1 in loaded
        assert plugin2 not in loaded
    
    def test_active_plugins_property(self):
        """Test active_plugins property."""
        plugin1 = MockPlugin("plugin1", "1.0.0")
        plugin2 = MockPlugin("plugin2", "1.0.0")
        
        # Set one plugin to active status
        plugin1.status = PluginStatus.ACTIVE
        
        asyncio.run(self.registry.register_plugin(plugin1, auto_initialize=False))
        asyncio.run(self.registry.register_plugin(plugin2, auto_initialize=False))
        
        active = self.registry.active_plugins
        assert len(active) == 1
        assert plugin1 in active
        assert plugin2 not in active


class TestGlobalRegistry:
    """Test global registry functions."""
    
    def setup_method(self):
        """Reset global registry before each test."""
        reset_global_registry()
    
    def test_get_global_registry(self):
        """Test getting global registry instance."""
        registry1 = get_global_registry()
        registry2 = get_global_registry()
        
        assert registry1 is registry2
        assert isinstance(registry1, PluginRegistry)
    
    def test_reset_global_registry(self):
        """Test resetting global registry."""
        registry1 = get_global_registry()
        reset_global_registry()
        registry2 = get_global_registry()
        
        assert registry1 is not registry2
        assert isinstance(registry2, PluginRegistry)


class TestPluginRegistryEdgeCases:
    """Test edge cases and error conditions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.registry = PluginRegistry()
    
    def test_get_plugins_by_type_empty(self):
        """Test getting plugins by type when none exist."""
        plugins = self.registry.get_plugins_by_type(PluginType.DETECTOR)
        assert plugins == []
    
    def test_get_plugin_not_found(self):
        """Test getting non-existent plugin."""
        plugin = self.registry.get_plugin("nonexistent")
        assert plugin is None
    
    def test_find_plugins_by_capability_edge_cases(self):
        """Test finding plugins by capability with edge cases."""
        plugin = MockPlugin("test_plugin", "1.0.0")
        plugin._metadata.empty_list = []
        plugin._metadata.single_value = "test"
        
        asyncio.run(self.registry.register_plugin(plugin, auto_initialize=False))
        
        # Test with empty list capability
        plugins = self.registry.find_plugins_by_capability("empty_list")
        assert len(plugins) == 0
        
        # Test with single value capability
        plugins = self.registry.find_plugins_by_capability("single_value", "test")
        assert len(plugins) == 1
        
        # Test with single value capability mismatch
        plugins = self.registry.find_plugins_by_capability("single_value", "other")
        assert len(plugins) == 0
    
    @pytest.mark.asyncio
    async def test_ensure_dependencies_missing_plugin(self):
        """Test ensuring dependencies with missing plugin."""
        plugin = MockPlugin("test_plugin", "1.0.0", dependencies=["missing"])
        await self.registry.register_plugin(plugin, auto_initialize=False)
        
        with pytest.raises(PluginInitializationError, match="Dependency 'missing' not found"):
            await self.registry._ensure_dependencies("test_plugin")
    
    @pytest.mark.asyncio
    async def test_ensure_dependencies_uninitialized_dependency(self):
        """Test ensuring dependencies with uninitialized dependency."""
        dep_plugin = MockPlugin("dependency", "1.0.0")
        plugin = MockPlugin("test_plugin", "1.0.0", dependencies=["dependency"])
        
        await self.registry.register_plugin(dep_plugin, auto_initialize=False)
        await self.registry.register_plugin(plugin, auto_initialize=False)
        
        assert not dep_plugin.is_initialized
        
        await self.registry._ensure_dependencies("test_plugin")
        
        assert dep_plugin.is_initialized
    
    def test_resolve_initialization_order_no_dependencies(self):
        """Test dependency resolution with no dependencies."""
        plugin1 = MockPlugin("plugin1", "1.0.0")
        plugin2 = MockPlugin("plugin2", "1.0.0")
        
        asyncio.run(self.registry.register_plugin(plugin1, auto_initialize=False))
        asyncio.run(self.registry.register_plugin(plugin2, auto_initialize=False))
        
        order = self.registry._resolve_initialization_order()
        
        assert len(order) == 2
        assert "plugin1" in order
        assert "plugin2" in order
    
    def test_resolve_initialization_order_missing_dependency_in_graph(self):
        """Test dependency resolution with dependency not in registry."""
        plugin = MockPlugin("plugin1", "1.0.0", dependencies=["external_dep"])
        asyncio.run(self.registry.register_plugin(plugin, auto_initialize=False))
        
        # Should not crash, just ignore missing dependencies in ordering
        order = self.registry._resolve_initialization_order()
        assert "plugin1" in order
