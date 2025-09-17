"""
Plugin registry for NetStealth Analyzer.

This module provides centralized plugin management including registration,
discovery, lifecycle management, and dependency resolution with full async support.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Set, Type, Union
from pathlib import Path
from collections import defaultdict

from .base import (
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

logger = logging.getLogger(__name__)


class PluginRegistry:
    """
    Central registry for managing plugins.
    
    Provides plugin discovery, registration, lifecycle management,
    and dependency resolution with comprehensive error handling.
    """
    
    def __init__(self):
        """Initialize plugin registry."""
        self._plugins: Dict[str, IPlugin] = {}
        self._plugin_classes: Dict[str, Type[IPlugin]] = {}
        self._plugins_by_type: Dict[PluginType, List[IPlugin]] = defaultdict(list)
        self._plugin_dependencies: Dict[str, Set[str]] = {}
        self._initialization_order: List[str] = []
        self._lock = asyncio.Lock()
    
    @property
    def plugin_count(self) -> int:
        """Get total number of registered plugins."""
        return len(self._plugins)
    
    @property
    def loaded_plugins(self) -> List[IPlugin]:
        """Get list of loaded plugins."""
        return [p for p in self._plugins.values() if p.status == PluginStatus.LOADED]
    
    @property
    def active_plugins(self) -> List[IPlugin]:
        """Get list of active plugins."""
        return [p for p in self._plugins.values() if p.status == PluginStatus.ACTIVE]
    
    def register_plugin_class(self, plugin_class: Type[IPlugin]) -> None:
        """
        Register a plugin class for later instantiation.
        
        Args:
            plugin_class: Plugin class to register
            
        Raises:
            PluginError: If plugin class is invalid or already registered
        """
        if not issubclass(plugin_class, IPlugin):
            raise PluginError(f"Plugin class {plugin_class.__name__} must inherit from IPlugin")
        
        # Create temporary instance to get metadata
        try:
            temp_instance = plugin_class()
            metadata = temp_instance.metadata
            plugin_name = metadata.name
        except Exception as e:
            raise PluginError(f"Failed to get metadata from plugin class {plugin_class.__name__}: {e}")
        
        if plugin_name in self._plugin_classes:
            raise PluginError(f"Plugin class with name '{plugin_name}' is already registered")
        
        self._plugin_classes[plugin_name] = plugin_class
        logger.info(f"Registered plugin class: {plugin_name} v{metadata.version}")
    
    async def register_plugin(self, plugin: IPlugin, auto_initialize: bool = True) -> None:
        """
        Register a plugin instance.
        
        Args:
            plugin: Plugin instance to register
            auto_initialize: Whether to automatically initialize the plugin
            
        Raises:
            PluginError: If plugin is invalid or registration fails
        """
        async with self._lock:
            plugin_name = plugin.name
            
            if plugin_name in self._plugins:
                raise PluginError(f"Plugin '{plugin_name}' is already registered")
            
            # Validate plugin
            if not self._validate_plugin(plugin):
                raise PluginError(f"Plugin '{plugin_name}' failed validation")
            
            # Register plugin
            self._plugins[plugin_name] = plugin
            self._plugins_by_type[plugin.plugin_type].append(plugin)
            
            # Track dependencies
            dependencies = set(plugin.metadata.dependencies)
            self._plugin_dependencies[plugin_name] = dependencies
            
            logger.info(f"Registered plugin: {plugin_name} v{plugin.version}")
            
            # Initialize if requested
            if auto_initialize:
                await self.initialize_plugin(plugin_name)
    
    async def unregister_plugin(self, plugin_name: str) -> None:
        """
        Unregister a plugin.
        
        Args:
            plugin_name: Name of plugin to unregister
            
        Raises:
            PluginError: If plugin is not found or unregistration fails
        """
        async with self._lock:
            if plugin_name not in self._plugins:
                raise PluginError(f"Plugin '{plugin_name}' is not registered")
            
            plugin = self._plugins[plugin_name]
            
            # Cleanup plugin if initialized
            if plugin.is_initialized:
                await plugin.cleanup()
            
            # Remove from registry
            del self._plugins[plugin_name]
            self._plugins_by_type[plugin.plugin_type].remove(plugin)
            
            if plugin_name in self._plugin_dependencies:
                del self._plugin_dependencies[plugin_name]
            
            if plugin_name in self._initialization_order:
                self._initialization_order.remove(plugin_name)
            
            logger.info(f"Unregistered plugin: {plugin_name}")
    
    async def initialize_plugin(self, plugin_name: str) -> None:
        """
        Initialize a specific plugin.
        
        Args:
            plugin_name: Name of plugin to initialize
            
        Raises:
            PluginInitializationError: If initialization fails
        """
        if plugin_name not in self._plugins:
            raise PluginInitializationError(f"Plugin '{plugin_name}' is not registered", plugin_name)
        
        plugin = self._plugins[plugin_name]
        
        if plugin.is_initialized:
            logger.warning(f"Plugin '{plugin_name}' is already initialized")
            return
        
        # Check dependencies
        await self._ensure_dependencies(plugin_name)
        
        try:
            await plugin.initialize()
            self._initialization_order.append(plugin_name)
            logger.info(f"Initialized plugin: {plugin_name}")
        except Exception as e:
            raise PluginInitializationError(f"Failed to initialize plugin '{plugin_name}': {e}", plugin_name, e)
    
    async def initialize_all_plugins(self) -> None:
        """Initialize all registered plugins in dependency order."""
        async with self._lock:
            # Get initialization order based on dependencies
            init_order = self._resolve_initialization_order()
            
            for plugin_name in init_order:
                if plugin_name in self._plugins and not self._plugins[plugin_name].is_initialized:
                    try:
                        await self.initialize_plugin(plugin_name)
                    except PluginInitializationError as e:
                        logger.error(f"Failed to initialize plugin '{plugin_name}': {e}")
                        # Continue with other plugins
    
    async def cleanup_all_plugins(self) -> None:
        """Cleanup all initialized plugins in reverse order."""
        async with self._lock:
            # Cleanup in reverse initialization order
            for plugin_name in reversed(self._initialization_order):
                if plugin_name in self._plugins:
                    plugin = self._plugins[plugin_name]
                    if plugin.is_initialized:
                        try:
                            await plugin.cleanup()
                            logger.info(f"Cleaned up plugin: {plugin_name}")
                        except Exception as e:
                            logger.error(f"Failed to cleanup plugin '{plugin_name}': {e}")
            
            self._initialization_order.clear()
    
    def get_plugin(self, plugin_name: str) -> Optional[IPlugin]:
        """Get plugin by name."""
        return self._plugins.get(plugin_name)
    
    def get_plugins_by_type(self, plugin_type: PluginType) -> List[IPlugin]:
        """Get all plugins of a specific type."""
        return self._plugins_by_type.get(plugin_type, [])
    
    def get_detector_plugins(self) -> List[IDetectorPlugin]:
        """Get all detector plugins."""
        return [p for p in self.get_plugins_by_type(PluginType.DETECTOR) if isinstance(p, IDetectorPlugin)]
    
    def get_parser_plugins(self) -> List[IParserPlugin]:
        """Get all parser plugins."""
        return [p for p in self.get_plugins_by_type(PluginType.PARSER) if isinstance(p, IParserPlugin)]
    
    def get_formatter_plugins(self) -> List[IFormatterPlugin]:
        """Get all formatter plugins."""
        return [p for p in self.get_plugins_by_type(PluginType.FORMATTER) if isinstance(p, IFormatterPlugin)]
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """Get list of all plugins with their metadata."""
        return [
            {
                'name': plugin.name,
                'version': plugin.version,
                'type': plugin.plugin_type.value,
                'status': plugin.status.value,
                'initialized': plugin.is_initialized,
                'metadata': plugin.metadata.to_dict()
            }
            for plugin in self._plugins.values()
        ]
    
    def find_plugins_by_capability(self, capability: str, value: Any = None) -> List[IPlugin]:
        """
        Find plugins by capability.
        
        Args:
            capability: Capability to search for (e.g., 'supported_formats', 'supported_categories')
            value: Optional specific value to match
            
        Returns:
            List of plugins that have the specified capability
        """
        matching_plugins = []
        
        for plugin in self._plugins.values():
            metadata = plugin.metadata
            
            if hasattr(metadata, capability):
                capability_value = getattr(metadata, capability)
                
                if value is None:
                    # Just check if capability exists and is not empty
                    if capability_value:
                        matching_plugins.append(plugin)
                else:
                    # Check if specific value is supported
                    if isinstance(capability_value, list) and value in capability_value:
                        matching_plugins.append(plugin)
                    elif capability_value == value:
                        matching_plugins.append(plugin)
        
        return matching_plugins
    
    async def create_plugin_from_class(self, plugin_name: str, config: Optional[Dict[str, Any]] = None) -> IPlugin:
        """
        Create plugin instance from registered class.
        
        Args:
            plugin_name: Name of plugin class to instantiate
            config: Optional configuration for the plugin
            
        Returns:
            Created plugin instance
            
        Raises:
            PluginError: If plugin class is not found or creation fails
        """
        if plugin_name not in self._plugin_classes:
            raise PluginError(f"Plugin class '{plugin_name}' is not registered")
        
        plugin_class = self._plugin_classes[plugin_name]
        
        try:
            # Try to create plugin with config parameter
            if config is not None:
                plugin = plugin_class(config=config)
            else:
                plugin = plugin_class()
            return plugin
        except Exception as e:
            raise PluginError(f"Failed to create plugin instance '{plugin_name}': {e}")
    
    def _validate_plugin(self, plugin: IPlugin) -> bool:
        """Validate plugin before registration."""
        try:
            # Check if plugin has required metadata
            metadata = plugin.metadata
            if not metadata.name or not metadata.version:
                return False
            
            # Check if plugin type is valid
            if not isinstance(metadata.plugin_type, PluginType):
                return False
            
            # Validate configuration if provided
            if plugin.config and not plugin.validate_config(plugin.config):
                return False
            
            return True
        except Exception:
            return False
    
    async def _ensure_dependencies(self, plugin_name: str) -> None:
        """Ensure all dependencies for a plugin are initialized."""
        dependencies = self._plugin_dependencies.get(plugin_name, set())
        
        for dep_name in dependencies:
            if dep_name not in self._plugins:
                raise PluginInitializationError(f"Dependency '{dep_name}' not found for plugin '{plugin_name}'", plugin_name)
            
            dep_plugin = self._plugins[dep_name]
            if not dep_plugin.is_initialized:
                await self.initialize_plugin(dep_name)
    
    def _resolve_initialization_order(self) -> List[str]:
        """Resolve plugin initialization order based on dependencies."""
        # Simple topological sort for dependency resolution
        visited = set()
        temp_visited = set()
        order = []
        
        def visit(plugin_name: str):
            if plugin_name in temp_visited:
                raise PluginError(f"Circular dependency detected involving plugin '{plugin_name}'")
            
            if plugin_name not in visited:
                temp_visited.add(plugin_name)
                
                # Visit dependencies first
                dependencies = self._plugin_dependencies.get(plugin_name, set())
                for dep_name in dependencies:
                    if dep_name in self._plugins:
                        visit(dep_name)
                
                temp_visited.remove(plugin_name)
                visited.add(plugin_name)
                order.append(plugin_name)
        
        # Visit all plugins
        for plugin_name in self._plugins.keys():
            if plugin_name not in visited:
                visit(plugin_name)
        
        return order
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        stats = {
            'total_plugins': len(self._plugins),
            'loaded_plugins': len(self.loaded_plugins),
            'active_plugins': len(self.active_plugins),
            'plugins_by_type': {
                plugin_type.value: len(plugins) 
                for plugin_type, plugins in self._plugins_by_type.items()
            },
            'initialization_order': self._initialization_order.copy()
        }
        
        return stats


# Global plugin registry instance
_global_registry: Optional[PluginRegistry] = None


def get_global_registry() -> PluginRegistry:
    """Get the global plugin registry instance."""
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginRegistry()
    return _global_registry


def reset_global_registry() -> None:
    """Reset the global plugin registry (mainly for testing)."""
    global _global_registry
    _global_registry = None
