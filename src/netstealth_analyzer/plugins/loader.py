"""
Plugin loader for NetStealth Analyzer.

This module provides dynamic plugin loading capabilities including file-based loading,
module discovery, and safe plugin instantiation with comprehensive error handling.
"""

import importlib
import importlib.util
import inspect
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union

from .base import IPlugin, PluginError, PluginLoadError
from .registry import PluginRegistry

logger = logging.getLogger(__name__)


class PluginLoader:
    """
    Dynamic plugin loader with support for file-based and module-based loading.
    
    Provides safe plugin discovery, loading, and instantiation with comprehensive
    error handling and validation.
    """
    
    def __init__(self, registry: Optional[PluginRegistry] = None):
        """Initialize plugin loader."""
        self.registry = registry
        self._loaded_modules: Dict[str, Any] = {}
    
    async def load_plugin_from_file(
        self, 
        file_path: Union[str, Path], 
        config: Optional[Dict[str, Any]] = None,
        auto_register: bool = True
    ) -> List[IPlugin]:
        """
        Load plugin(s) from a Python file.
        
        Args:
            file_path: Path to the plugin file
            config: Optional configuration for the plugin(s)
            auto_register: Whether to automatically register loaded plugins
            
        Returns:
            List of loaded plugin instances
            
        Raises:
            PluginLoadError: If loading fails
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise PluginLoadError(f"Plugin file not found: {file_path}")
        
        if not file_path.suffix == '.py':
            raise PluginLoadError(f"Plugin file must be a Python file: {file_path}")
        
        try:
            # Load module from file
            module_name = f"plugin_{file_path.stem}_{id(file_path)}"
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            
            if spec is None or spec.loader is None:
                raise PluginLoadError(f"Failed to create module spec for: {file_path}")
            
            module = importlib.util.module_from_spec(spec)
            
            # Execute module
            spec.loader.exec_module(module)
            self._loaded_modules[module_name] = module
            
            # Find plugin classes in module
            plugin_classes = self._find_plugin_classes(module)
            
            if not plugin_classes:
                raise PluginLoadError(f"No plugin classes found in: {file_path}")
            
            # Create plugin instances
            plugins = []
            for plugin_class in plugin_classes:
                try:
                    plugin = plugin_class(config)
                    plugins.append(plugin)
                    
                    logger.info(f"Loaded plugin: {plugin.name} v{plugin.version} from {file_path}")
                    
                    # Register plugin if requested
                    if auto_register and self.registry:
                        await self.registry.register_plugin(plugin)
                        
                except Exception as e:
                    logger.error(f"Failed to create plugin instance from class {plugin_class.__name__}: {e}")
                    # Continue with other plugin classes
            
            if not plugins:
                raise PluginLoadError(f"Failed to create any plugin instances from: {file_path}")
            
            return plugins
            
        except Exception as e:
            if isinstance(e, PluginLoadError):
                raise
            raise PluginLoadError(f"Failed to load plugin from {file_path}: {e}")
    
    async def load_plugin_from_module(
        self, 
        module_name: str, 
        config: Optional[Dict[str, Any]] = None,
        auto_register: bool = True
    ) -> List[IPlugin]:
        """
        Load plugin(s) from a Python module.
        
        Args:
            module_name: Name of the module to load
            config: Optional configuration for the plugin(s)
            auto_register: Whether to automatically register loaded plugins
            
        Returns:
            List of loaded plugin instances
            
        Raises:
            PluginLoadError: If loading fails
        """
        try:
            # Import module
            module = importlib.import_module(module_name)
            self._loaded_modules[module_name] = module
            
            # Find plugin classes in module
            plugin_classes = self._find_plugin_classes(module)
            
            if not plugin_classes:
                raise PluginLoadError(f"No plugin classes found in module: {module_name}")
            
            # Create plugin instances
            plugins = []
            for plugin_class in plugin_classes:
                try:
                    plugin = plugin_class(config)
                    plugins.append(plugin)
                    
                    logger.info(f"Loaded plugin: {plugin.name} v{plugin.version} from module {module_name}")
                    
                    # Register plugin if requested
                    if auto_register and self.registry:
                        await self.registry.register_plugin(plugin)
                        
                except Exception as e:
                    logger.error(f"Failed to create plugin instance from class {plugin_class.__name__}: {e}")
                    # Continue with other plugin classes
            
            if not plugins:
                raise PluginLoadError(f"Failed to create any plugin instances from module: {module_name}")
            
            return plugins
            
        except ImportError as e:
            raise PluginLoadError(f"Failed to import module {module_name}: {e}")
        except Exception as e:
            if isinstance(e, PluginLoadError):
                raise
            raise PluginLoadError(f"Failed to load plugin from module {module_name}: {e}")
    
    async def discover_plugins_in_directory(
        self, 
        directory: Union[str, Path], 
        recursive: bool = True,
        config: Optional[Dict[str, Any]] = None,
        auto_register: bool = True
    ) -> List[IPlugin]:
        """
        Discover and load all plugins in a directory.
        
        Args:
            directory: Directory to search for plugins
            recursive: Whether to search subdirectories
            config: Optional configuration for the plugin(s)
            auto_register: Whether to automatically register loaded plugins
            
        Returns:
            List of loaded plugin instances
        """
        directory = Path(directory)
        
        if not directory.exists():
            raise PluginLoadError(f"Plugin directory not found: {directory}")
        
        if not directory.is_dir():
            raise PluginLoadError(f"Path is not a directory: {directory}")
        
        plugins = []
        
        # Find Python files
        pattern = "**/*.py" if recursive else "*.py"
        python_files = list(directory.glob(pattern))
        
        # Filter out __init__.py and __pycache__
        python_files = [
            f for f in python_files 
            if f.name != "__init__.py" and "__pycache__" not in str(f)
        ]
        
        logger.info(f"Found {len(python_files)} Python files in {directory}")
        
        # Load plugins from each file
        for file_path in python_files:
            try:
                file_plugins = await self.load_plugin_from_file(
                    file_path, 
                    config=config, 
                    auto_register=auto_register
                )
                plugins.extend(file_plugins)
                
            except PluginLoadError as e:
                logger.warning(f"Failed to load plugin from {file_path}: {e}")
                # Continue with other files
            except Exception as e:
                logger.error(f"Unexpected error loading plugin from {file_path}: {e}")
                # Continue with other files
        
        logger.info(f"Successfully loaded {len(plugins)} plugins from {directory}")
        return plugins
    
    async def load_plugin_class(
        self, 
        plugin_class: Type[IPlugin], 
        config: Optional[Dict[str, Any]] = None,
        auto_register: bool = True
    ) -> IPlugin:
        """
        Load plugin from a class.
        
        Args:
            plugin_class: Plugin class to instantiate
            config: Optional configuration for the plugin
            auto_register: Whether to automatically register the plugin
            
        Returns:
            Loaded plugin instance
            
        Raises:
            PluginLoadError: If loading fails
        """
        if not issubclass(plugin_class, IPlugin):
            raise PluginLoadError(f"Class {plugin_class.__name__} is not a valid plugin class")
        
        try:
            plugin = plugin_class(config)
            
            logger.info(f"Loaded plugin: {plugin.name} v{plugin.version} from class {plugin_class.__name__}")
            
            # Register plugin if requested
            if auto_register and self.registry:
                await self.registry.register_plugin(plugin)
            
            return plugin
            
        except Exception as e:
            raise PluginLoadError(f"Failed to create plugin instance from class {plugin_class.__name__}: {e}")
    
    def _find_plugin_classes(self, module: Any) -> List[Type[IPlugin]]:
        """Find all plugin classes in a module."""
        plugin_classes = []
        
        for name, obj in inspect.getmembers(module, inspect.isclass):
            # Skip imported classes (only include classes defined in this module)
            if obj.__module__ != module.__name__:
                continue
            
            # Check if it's a plugin class
            if issubclass(obj, IPlugin) and obj != IPlugin:
                # Skip abstract base classes
                if not inspect.isabstract(obj):
                    plugin_classes.append(obj)
        
        return plugin_classes
    
    def get_loaded_modules(self) -> Dict[str, Any]:
        """Get dictionary of loaded modules."""
        return self._loaded_modules.copy()
    
    def unload_module(self, module_name: str) -> None:
        """
        Unload a module (remove from cache).
        
        Args:
            module_name: Name of module to unload
        """
        if module_name in self._loaded_modules:
            del self._loaded_modules[module_name]
        
        # Remove from sys.modules if present
        if module_name in sys.modules:
            del sys.modules[module_name]
        
        logger.info(f"Unloaded module: {module_name}")
    
    def reload_module(self, module_name: str) -> Any:
        """
        Reload a module.
        
        Args:
            module_name: Name of module to reload
            
        Returns:
            Reloaded module
            
        Raises:
            PluginLoadError: If reload fails
        """
        try:
            if module_name in sys.modules:
                module = importlib.reload(sys.modules[module_name])
            else:
                module = importlib.import_module(module_name)
            
            self._loaded_modules[module_name] = module
            logger.info(f"Reloaded module: {module_name}")
            return module
            
        except Exception as e:
            raise PluginLoadError(f"Failed to reload module {module_name}: {e}")
    
    def validate_plugin_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Validate a plugin file without loading it.
        
        Args:
            file_path: Path to the plugin file
            
        Returns:
            Validation result with metadata
        """
        file_path = Path(file_path)
        result = {
            'valid': False,
            'file_path': str(file_path),
            'errors': [],
            'warnings': [],
            'plugin_classes': []
        }
        
        if not file_path.exists():
            result['errors'].append("File does not exist")
            return result
        
        if not file_path.suffix == '.py':
            result['errors'].append("File is not a Python file")
            return result
        
        try:
            # Try to compile the file
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            
            compile(source, str(file_path), 'exec')
            
            # Try to load module temporarily
            module_name = f"temp_validation_{file_path.stem}_{id(file_path)}"
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            
            if spec is None or spec.loader is None:
                result['errors'].append("Failed to create module spec")
                return result
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin classes
            plugin_classes = self._find_plugin_classes(module)
            
            if not plugin_classes:
                result['warnings'].append("No plugin classes found")
            else:
                result['valid'] = True
                
                for plugin_class in plugin_classes:
                    try:
                        # Try to create temporary instance to get metadata
                        temp_plugin = plugin_class()
                        metadata = temp_plugin.metadata
                        
                        result['plugin_classes'].append({
                            'class_name': plugin_class.__name__,
                            'plugin_name': metadata.name,
                            'version': metadata.version,
                            'plugin_type': metadata.plugin_type.value,
                            'description': metadata.description
                        })
                        
                    except Exception as e:
                        result['warnings'].append(f"Failed to get metadata from {plugin_class.__name__}: {e}")
            
        except SyntaxError as e:
            result['errors'].append(f"Syntax error: {e}")
        except Exception as e:
            result['errors'].append(f"Validation error: {e}")
        
        return result
    
    def get_loader_stats(self) -> Dict[str, Any]:
        """Get loader statistics."""
        return {
            'loaded_modules': len(self._loaded_modules),
            'module_names': list(self._loaded_modules.keys())
        }


# Convenience functions for common operations

async def load_plugin_from_file(
    file_path: Union[str, Path], 
    config: Optional[Dict[str, Any]] = None,
    registry: Optional[PluginRegistry] = None
) -> List[IPlugin]:
    """
    Convenience function to load plugin from file.
    
    Args:
        file_path: Path to the plugin file
        config: Optional configuration for the plugin(s)
        registry: Optional registry to use (uses global if not provided)
        
    Returns:
        List of loaded plugin instances
    """
    loader = PluginLoader(registry)
    return await loader.load_plugin_from_file(file_path, config)


async def discover_plugins(
    directory: Union[str, Path], 
    recursive: bool = True,
    config: Optional[Dict[str, Any]] = None,
    registry: Optional[PluginRegistry] = None
) -> List[IPlugin]:
    """
    Convenience function to discover plugins in directory.
    
    Args:
        directory: Directory to search for plugins
        recursive: Whether to search subdirectories
        config: Optional configuration for the plugin(s)
        registry: Optional registry to use (uses global if not provided)
        
    Returns:
        List of loaded plugin instances
    """
    loader = PluginLoader(registry)
    return await loader.discover_plugins_in_directory(directory, recursive, config)
