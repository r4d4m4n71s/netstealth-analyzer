"""
Unit tests for NetStealth Analyzer plugin loader system.

Tests dynamic plugin loading, module discovery, validation, and safe plugin
instantiation with comprehensive error handling.
"""

import pytest
import asyncio
import tempfile
import importlib
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, AsyncMock, mock_open
from typing import Any, Dict, List, Optional, Type

from src.netstealth_analyzer.plugins.loader import (
    PluginLoader,
    load_plugin_from_file,
    discover_plugins,
)
from src.netstealth_analyzer.plugins.base import (
    IPlugin,
    PluginMetadata,
    PluginType,
    PluginStatus,
    PluginLoadError,
)
from src.netstealth_analyzer.plugins.registry import PluginRegistry


# Mock plugin classes for testing
class MockPlugin(IPlugin):
    """Mock plugin for testing."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="mock_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Mock plugin for testing"
        )
    
    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata


class AnotherMockPlugin(IPlugin):
    """Another mock plugin for testing multiple plugins."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="another_mock_plugin",
            version="2.0.0",
            plugin_type=PluginType.PARSER,
            description="Another mock plugin for testing"
        )
    
    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata


class BrokenPlugin(IPlugin):
    """Plugin that raises an error during initialization."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        raise ValueError("Broken plugin initialization")
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="broken_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Broken plugin"
        )


class TestPluginLoader:
    """Test PluginLoader class."""
    
    def test_loader_initialization(self):
        """Test PluginLoader initialization."""
        loader = PluginLoader()
        
        assert loader.registry is None
        assert loader._loaded_modules == {}
    
    def test_loader_initialization_with_registry(self):
        """Test PluginLoader initialization with registry."""
        registry = Mock(spec=PluginRegistry)
        loader = PluginLoader(registry)
        
        assert loader.registry is registry
        assert loader._loaded_modules == {}
    
    @pytest.mark.asyncio
    async def test_load_plugin_from_file_not_found(self):
        """Test loading plugin from non-existent file."""
        loader = PluginLoader()
        
        with pytest.raises(PluginLoadError, match="Plugin file not found"):
            await loader.load_plugin_from_file("/nonexistent/file.py")
    
    @pytest.mark.asyncio
    async def test_load_plugin_from_file_not_python(self):
        """Test loading plugin from non-Python file."""
        loader = PluginLoader()
        
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        
        try:
            with pytest.raises(PluginLoadError, match="must be a Python file"):
                await loader.load_plugin_from_file(tmp_path)
        finally:
            tmp_path.unlink()
    
    @pytest.mark.asyncio
    async def test_load_plugin_from_file_success(self):
        """Test successful plugin loading from file."""
        loader = PluginLoader()
        
        # Create a temporary Python file with a plugin class
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class TestFilePlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="test_file_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Test plugin from file"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=".py", delete=False) as tmp:
            tmp.write(plugin_code)
            tmp_path = Path(tmp.name)
        
        try:
            plugins = await loader.load_plugin_from_file(tmp_path)
            
            assert len(plugins) == 1
            assert plugins[0].name == "test_file_plugin"
            assert plugins[0].version == "1.0.0"
            assert len(loader._loaded_modules) == 1
            
        finally:
            tmp_path.unlink()
    
    @pytest.mark.asyncio
    async def test_load_plugin_from_file_with_registry(self):
        """Test plugin loading with automatic registration."""
        registry = AsyncMock(spec=PluginRegistry)
        loader = PluginLoader(registry)
        
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class TestRegistryPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="test_registry_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Test plugin with registry"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=".py", delete=False) as tmp:
            tmp.write(plugin_code)
            tmp_path = Path(tmp.name)
        
        try:
            plugins = await loader.load_plugin_from_file(tmp_path, auto_register=True)
            
            assert len(plugins) == 1
            registry.register_plugin.assert_called_once_with(plugins[0])
            
        finally:
            tmp_path.unlink()
    
    @pytest.mark.asyncio
    async def test_load_plugin_from_file_no_plugins(self):
        """Test loading file with no plugin classes."""
        loader = PluginLoader()
        
        # Create a Python file without plugin classes
        code = '''
def some_function():
    return "not a plugin"

class NotAPlugin:
    pass
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=".py", delete=False) as tmp:
            tmp.write(code)
            tmp_path = Path(tmp.name)
        
        try:
            with pytest.raises(PluginLoadError, match="No plugin classes found"):
                await loader.load_plugin_from_file(tmp_path)
        finally:
            tmp_path.unlink()
    
    @pytest.mark.asyncio
    async def test_load_plugin_from_file_syntax_error(self):
        """Test loading file with syntax error."""
        loader = PluginLoader()
        
        # Create a Python file with syntax error
        code = '''
def broken_syntax(
    # Missing closing parenthesis
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=".py", delete=False) as tmp:
            tmp.write(code)
            tmp_path = Path(tmp.name)
        
        try:
            with pytest.raises(PluginLoadError, match="Failed to load plugin"):
                await loader.load_plugin_from_file(tmp_path)
        finally:
            tmp_path.unlink()
    
    @pytest.mark.asyncio
    async def test_load_plugin_from_module_success(self):
        """Test successful plugin loading from module."""
        loader = PluginLoader()
        
        # Mock a module with plugin classes
        mock_module = MagicMock()
        mock_module.__name__ = "test_module"
        
        # Create mock plugin class
        mock_plugin_class = Mock()
        mock_plugin_class.__name__ = "MockPluginClass"
        mock_plugin_class.__module__ = "test_module"
        
        # Create mock plugin instance
        mock_plugin = Mock(spec=IPlugin)
        mock_plugin.name = "test_module_plugin"
        mock_plugin.version = "1.0.0"
        mock_plugin_class.return_value = mock_plugin
        
        # Set up module members
        mock_module.MockPluginClass = mock_plugin_class
        
        with patch('importlib.import_module', return_value=mock_module):
            with patch.object(loader, '_find_plugin_classes', return_value=[mock_plugin_class]):
                plugins = await loader.load_plugin_from_module("test_module")
                
                assert len(plugins) == 1
                assert plugins[0] is mock_plugin
                assert "test_module" in loader._loaded_modules
    
    @pytest.mark.asyncio
    async def test_load_plugin_from_module_import_error(self):
        """Test loading plugin from non-existent module."""
        loader = PluginLoader()
        
        with patch('importlib.import_module', side_effect=ImportError("No module named 'nonexistent'")):
            with pytest.raises(PluginLoadError, match="Failed to import module"):
                await loader.load_plugin_from_module("nonexistent")
    
    @pytest.mark.asyncio
    async def test_load_plugin_from_module_no_plugins(self):
        """Test loading module with no plugin classes."""
        loader = PluginLoader()
        
        mock_module = MagicMock()
        mock_module.__name__ = "empty_module"
        
        with patch('importlib.import_module', return_value=mock_module):
            with patch.object(loader, '_find_plugin_classes', return_value=[]):
                with pytest.raises(PluginLoadError, match="No plugin classes found"):
                    await loader.load_plugin_from_module("empty_module")
    
    @pytest.mark.asyncio
    async def test_discover_plugins_in_directory_not_found(self):
        """Test plugin discovery in non-existent directory."""
        loader = PluginLoader()
        
        with pytest.raises(PluginLoadError, match="Plugin directory not found"):
            await loader.discover_plugins_in_directory("/nonexistent/directory")
    
    @pytest.mark.asyncio
    async def test_discover_plugins_in_directory_not_dir(self):
        """Test plugin discovery on a file instead of directory."""
        loader = PluginLoader()
        
        with tempfile.NamedTemporaryFile() as tmp:
            with pytest.raises(PluginLoadError, match="Path is not a directory"):
                await loader.discover_plugins_in_directory(tmp.name)
    
    @pytest.mark.asyncio
    async def test_discover_plugins_in_directory_success(self):
        """Test successful plugin discovery in directory."""
        loader = PluginLoader()
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            
            # Create plugin files
            plugin1_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class Plugin1(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="plugin1",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin 1"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''
            
            plugin2_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class Plugin2(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="plugin2",
            version="2.0.0",
            plugin_type=PluginType.PARSER,
            description="Plugin 2"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''
            
            # Write plugin files
            (tmp_path / "plugin1.py").write_text(plugin1_code)
            (tmp_path / "plugin2.py").write_text(plugin2_code)
            
            # Create __init__.py (should be ignored)
            (tmp_path / "__init__.py").write_text("")
            
            plugins = await loader.discover_plugins_in_directory(tmp_path)
            
            assert len(plugins) == 2
            plugin_names = {p.name for p in plugins}
            assert plugin_names == {"plugin1", "plugin2"}
    
    @pytest.mark.asyncio
    async def test_discover_plugins_recursive(self):
        """Test recursive plugin discovery."""
        loader = PluginLoader()
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            
            # Create subdirectory
            sub_dir = tmp_path / "subdir"
            sub_dir.mkdir()
            
            plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class SubPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="sub_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Sub plugin"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''
            
            (sub_dir / "sub_plugin.py").write_text(plugin_code)
            
            # Test recursive discovery
            plugins = await loader.discover_plugins_in_directory(tmp_path, recursive=True)
            assert len(plugins) == 1
            assert plugins[0].name == "sub_plugin"
            
            # Test non-recursive discovery
            plugins = await loader.discover_plugins_in_directory(tmp_path, recursive=False)
            assert len(plugins) == 0
    
    @pytest.mark.asyncio
    async def test_load_plugin_class_success(self):
        """Test loading plugin from class."""
        loader = PluginLoader()
        
        plugin = await loader.load_plugin_class(MockPlugin)
        
        assert isinstance(plugin, MockPlugin)
        assert plugin.name == "mock_plugin"
        assert plugin.version == "1.0.0"
    
    @pytest.mark.asyncio
    async def test_load_plugin_class_invalid(self):
        """Test loading invalid plugin class."""
        loader = PluginLoader()
        
        class NotAPlugin:
            pass
        
        with pytest.raises(PluginLoadError, match="is not a valid plugin class"):
            await loader.load_plugin_class(NotAPlugin)
    
    @pytest.mark.asyncio
    async def test_load_plugin_class_with_registry(self):
        """Test loading plugin class with registry."""
        registry = AsyncMock(spec=PluginRegistry)
        loader = PluginLoader(registry)
        
        plugin = await loader.load_plugin_class(MockPlugin, auto_register=True)
        
        registry.register_plugin.assert_called_once_with(plugin)
    
    @pytest.mark.asyncio
    async def test_load_plugin_class_initialization_error(self):
        """Test loading plugin class that fails initialization."""
        loader = PluginLoader()
        
        with pytest.raises(PluginLoadError, match="Failed to create plugin instance"):
            await loader.load_plugin_class(BrokenPlugin)
    
    def test_find_plugin_classes(self):
        """Test finding plugin classes in module."""
        loader = PluginLoader()
        
        # Create mock module
        mock_module = MagicMock()
        mock_module.__name__ = "test_module"
        
        # Create mock classes
        plugin_class = Mock()
        plugin_class.__name__ = "PluginClass"
        plugin_class.__module__ = "test_module"
        
        non_plugin_class = Mock()
        non_plugin_class.__name__ = "NonPluginClass"
        non_plugin_class.__module__ = "test_module"
        
        imported_class = Mock()
        imported_class.__name__ = "ImportedClass"
        imported_class.__module__ = "other_module"
        
        # Set up issubclass behavior
        def mock_issubclass(cls, base):
            if cls is plugin_class and base is IPlugin:
                return True
            if cls is IPlugin and base is IPlugin:
                return True
            return False
        
        with patch('inspect.getmembers') as mock_getmembers:
            with patch('inspect.isclass', return_value=True):
                with patch('builtins.issubclass', side_effect=mock_issubclass):
                    with patch('inspect.isabstract', return_value=False):
                        mock_getmembers.return_value = [
                            ("PluginClass", plugin_class),
                            ("NonPluginClass", non_plugin_class),
                            ("ImportedClass", imported_class),
                            ("IPlugin", IPlugin)
                        ]
                        
                        classes = loader._find_plugin_classes(mock_module)
                        
                        assert len(classes) == 1
                        assert classes[0] is plugin_class
    
    def test_get_loaded_modules(self):
        """Test getting loaded modules."""
        loader = PluginLoader()
        loader._loaded_modules = {"module1": "mock1", "module2": "mock2"}
        
        modules = loader.get_loaded_modules()
        
        assert modules == {"module1": "mock1", "module2": "mock2"}
        # Ensure it's a copy
        modules["module3"] = "mock3"
        assert "module3" not in loader._loaded_modules
    
    def test_unload_module(self):
        """Test unloading module."""
        loader = PluginLoader()
        loader._loaded_modules = {"test_module": "mock_module"}
        
        with patch.dict('sys.modules', {"test_module": "mock_sys_module"}):
            loader.unload_module("test_module")
            
            assert "test_module" not in loader._loaded_modules
            assert "test_module" not in sys.modules
    
    def test_unload_module_not_loaded(self):
        """Test unloading module that wasn't loaded."""
        loader = PluginLoader()
        
        # Should not raise error
        loader.unload_module("nonexistent_module")
    
    def test_reload_module_success(self):
        """Test successful module reload."""
        loader = PluginLoader()
        mock_module = MagicMock()
        
        with patch('importlib.reload', return_value=mock_module) as mock_reload:
            with patch.dict('sys.modules', {"test_module": "old_module"}):
                result = loader.reload_module("test_module")
                
                assert result is mock_module
                assert loader._loaded_modules["test_module"] is mock_module
                mock_reload.assert_called_once_with("old_module")
    
    def test_reload_module_not_in_sys(self):
        """Test reloading module not in sys.modules."""
        loader = PluginLoader()
        mock_module = MagicMock()
        
        with patch('importlib.import_module', return_value=mock_module) as mock_import:
            result = loader.reload_module("new_module")
            
            assert result is mock_module
            assert loader._loaded_modules["new_module"] is mock_module
            mock_import.assert_called_once_with("new_module")
    
    def test_reload_module_error(self):
        """Test module reload error."""
        loader = PluginLoader()
        
        with patch('importlib.reload', side_effect=ImportError("Reload failed")):
            with patch.dict('sys.modules', {"test_module": "old_module"}):
                with pytest.raises(PluginLoadError, match="Failed to reload module"):
                    loader.reload_module("test_module")
    
    def test_validate_plugin_file_not_found(self):
        """Test validating non-existent file."""
        loader = PluginLoader()
        
        result = loader.validate_plugin_file("/nonexistent/file.py")
        
        assert result['valid'] is False
        assert "File does not exist" in result['errors']
    
    def test_validate_plugin_file_not_python(self):
        """Test validating non-Python file."""
        loader = PluginLoader()
        
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        
        try:
            result = loader.validate_plugin_file(tmp_path)
            
            assert result['valid'] is False
            assert "File is not a Python file" in result['errors']
        finally:
            tmp_path.unlink()
    
    def test_validate_plugin_file_syntax_error(self):
        """Test validating file with syntax error."""
        loader = PluginLoader()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=".py", delete=False) as tmp:
            tmp.write("def broken_syntax(\n")  # Missing closing parenthesis
            tmp_path = Path(tmp.name)
        
        try:
            result = loader.validate_plugin_file(tmp_path)
            
            assert result['valid'] is False
            assert any("Syntax error" in error for error in result['errors'])
        finally:
            tmp_path.unlink()
    
    def test_validate_plugin_file_success(self):
        """Test successful file validation."""
        loader = PluginLoader()
        
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class ValidPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="valid_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Valid plugin"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=".py", delete=False) as tmp:
            tmp.write(plugin_code)
            tmp_path = Path(tmp.name)
        
        try:
            result = loader.validate_plugin_file(tmp_path)
            
            assert result['valid'] is True
            assert len(result['plugin_classes']) == 1
            assert result['plugin_classes'][0]['plugin_name'] == "valid_plugin"
        finally:
            tmp_path.unlink()
    
    def test_validate_plugin_file_no_plugins(self):
        """Test validating file with no plugin classes."""
        loader = PluginLoader()
        
        code = '''
def some_function():
    return "not a plugin"
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=".py", delete=False) as tmp:
            tmp.write(code)
            tmp_path = Path(tmp.name)
        
        try:
            result = loader.validate_plugin_file(tmp_path)
            
            assert result['valid'] is False
            assert "No plugin classes found" in result['warnings']
        finally:
            tmp_path.unlink()
    
    def test_get_loader_stats(self):
        """Test getting loader statistics."""
        loader = PluginLoader()
        loader._loaded_modules = {"module1": "mock1", "module2": "mock2"}
        
        stats = loader.get_loader_stats()
        
        assert stats['loaded_modules'] == 2
        assert set(stats['module_names']) == {"module1", "module2"}


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    @pytest.mark.asyncio
    async def test_load_plugin_from_file_convenience(self):
        """Test load_plugin_from_file convenience function."""
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class ConveniencePlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="convenience_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Convenience plugin"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=".py", delete=False) as tmp:
            tmp.write(plugin_code)
            tmp_path = Path(tmp.name)
        
        try:
            plugins = await load_plugin_from_file(tmp_path)
            
            assert len(plugins) == 1
            assert plugins[0].name == "convenience_plugin"
        finally:
            tmp_path.unlink()
    
    @pytest.mark.asyncio
    async def test_discover_plugins_convenience(self):
        """Test discover_plugins convenience function."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            
            plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class DiscoveredPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="discovered_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Discovered plugin"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''
            
            (tmp_path / "discovered.py").write_text(plugin_code)
            
            plugins = await discover_plugins(tmp_path)
            
            assert len(plugins) == 1
            assert plugins[0].name == "discovered_plugin"


class TestLoaderIntegration:
    """Integration tests for loader functionality."""
    
    @pytest.mark.asyncio
    async def test_full_loading_workflow(self):
        """Test complete plugin loading workflow."""
        registry = AsyncMock(spec=PluginRegistry)
        loader = PluginLoader(registry)
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            
            # Create multiple plugin files
            plugin1_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class WorkflowPlugin1(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="workflow_plugin1",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Workflow plugin 1"
        )
    
    @property
    def metadata(self):
        return self._metadata

class WorkflowPlugin2(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="workflow_plugin2",
            version="1.0.0",
            plugin_type=PluginType.PARSER,
            description="Workflow plugin 2"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''
            
            (tmp_path / "workflow_plugins.py").write_text(plugin1_code)
            
            # Load plugins from directory
            plugins = await loader.discover_plugins_in_directory(tmp_path)
            
            assert len(plugins) == 2
            plugin_names = {p.name for p in plugins}
            assert plugin_names == {"workflow_plugin1", "workflow_plugin2"}
            
            # Verify registration was called
            assert registry.register_plugin.call_count == 2
            
            # Check loader stats
            stats = loader.get_loader_stats()
            assert stats['loaded_modules'] == 1
    
    @pytest.mark.asyncio
    async def test_error_handling_in_discovery(self):
        """Test error handling during plugin discovery."""
        loader = PluginLoader()
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            
            # Create valid plugin
            valid_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class ValidPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="valid_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Valid plugin"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''
            
            # Create invalid plugin (syntax error)
            invalid_code = '''
def broken_syntax(
    # Missing closing parenthesis
'''
            
            (tmp_path / "valid.py").write_text(valid_code)
            (tmp_path / "invalid.py").write_text(invalid_code)
            
            # Should load valid plugin and skip invalid one
            plugins = await loader.discover_plugins_in_directory(tmp_path)
            
            assert len(plugins) == 1
            assert plugins[0].name == "valid_plugin"
    
    @pytest.mark.asyncio
    async def test_plugin_with_config(self):
        """Test loading plugin with configuration."""
        loader = PluginLoader()
        
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class ConfigurablePlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="configurable_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Configurable plugin"
        )
        self.test_config = config.get("test_value", "default") if config else "default"
    
    @property
    def metadata(self):
        return self._metadata
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=".py", delete=False) as tmp:
            tmp.write(plugin_code)
            tmp_path = Path(tmp.name)
        
        try:
            config = {"test_value": "configured"}
            plugins = await loader.load_plugin_from_file(tmp_path, config=config)
            
            assert len(plugins) == 1
            assert plugins[0].test_config == "configured"
        finally:
            tmp_path.unlink()
    
    @pytest.mark.asyncio
    async def test_module_management(self):
        """Test module loading, unloading, and reloading."""
        loader = PluginLoader()
        
        # Mock module
        mock_module = MagicMock()
        mock_module.__name__ = "test_module"
        
        with patch('importlib.import_module', return_value=mock_module):
            with patch.object(loader, '_find_plugin_classes', return_value=[]):
                # This will fail due to no plugins, but module should be loaded
                try:
                    await loader.load_plugin_from_module("test_module")
                except PluginLoadError:
                    pass
                
                # Module should be in loaded modules
                assert "test_module" in loader._loaded_modules
                
                # Test unloading
                loader.unload_module("test_module")
                assert "test_module" not in loader._loaded_modules
    
    @pytest.mark.asyncio
    async def test_partial_plugin_loading_failure(self):
        """Test handling when some plugins fail to load from a file."""
        loader = PluginLoader()
        
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class GoodPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="good_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Good plugin"
        )
    
    @property
    def metadata(self):
        return self._metadata

class BadPlugin(IPlugin):
    def __init__(self, config=None):
        raise ValueError("Bad plugin initialization")
    
    @property
    def metadata(self):
        return PluginMetadata(
            name="bad_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Bad plugin"
        )
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=".py", delete=False) as tmp:
            tmp.write(plugin_code)
            tmp_path = Path(tmp.name)
        
        try:
            plugins = await loader.load_plugin_from_file(tmp_path)
            
            # Should load only the good plugin
            assert len(plugins) == 1
            assert plugins[0].name == "good_plugin"
        finally:
            tmp_path.unlink()
    
    def test_validate_plugin_file_metadata_error(self):
        """Test validation when plugin metadata extraction fails."""
        loader = PluginLoader()
        
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class ProblematicPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        # This will cause metadata access to fail
        self._metadata = None
    
    @property
    def metadata(self):
        if self._metadata is None:
            raise RuntimeError("Metadata not available")
        return self._metadata
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=".py", delete=False) as tmp:
            tmp.write(plugin_code)
            tmp_path = Path(tmp.name)
        
        try:
            result = loader.validate_plugin_file(tmp_path)
            
            # Should still be valid but have warnings
            assert result['valid'] is True
            assert len(result['warnings']) > 0
            assert any("Failed to get metadata" in warning for warning in result['warnings'])
        finally:
            tmp_path.unlink()
