"""
Actor Registry for the Network Actor Detection System.

This module provides dynamic loading and management of network actors,
following the same pattern as the parser and detector registries.

Author: NetStealth Analyzer Team
Version: 1.0.0
Python: 3.13+
"""

from typing import Dict, List, Optional, Type, Any
import logging

from .base import NetworkActor, ActorCategory
from .proxy import ProxyActor


logger = logging.getLogger(__name__)


class ActorRegistry:
    """
    Registry for managing network actors.
    
    Provides dynamic loading, registration, and retrieval of network actors
    with support for lazy loading and error handling.
    """
    
    def __init__(self):
        """Initialize the actor registry."""
        self._actors: Dict[str, Type[NetworkActor]] = {}
        self._instances: Dict[str, NetworkActor] = {}
        self._initialized = False
    
    def _ensure_initialized(self) -> None:
        """Ensure the registry is initialized with default actors."""
        if not self._initialized:
            self._register_default_actors()
            self._initialized = True
    
    def _register_default_actors(self) -> None:
        """Register default network actors."""
        try:
            # Register ProxyActor
            self.register("proxy", ProxyActor)
            logger.debug("Registered ProxyActor")
            
            # Future actors will be registered here when implemented
            # self.register("vpn", VPNActor)
            # self.register("cdn", CDNActor)
            # self.register("load_balancer", LoadBalancerActor)
            # self.register("security_service", SecurityServiceActor)
            
        except Exception as e:
            logger.error(f"Failed to register default actors: {e}")
    
    def register(self, actor_type: str, actor_class: Type[NetworkActor]) -> None:
        """
        Register a network actor class.
        
        Args:
            actor_type: Unique identifier for the actor type
            actor_class: NetworkActor class to register
            
        Raises:
            ValueError: If actor_type is already registered or invalid
            TypeError: If actor_class is not a NetworkActor subclass
        """
        if not isinstance(actor_type, str) or not actor_type.strip():
            raise ValueError("Actor type must be a non-empty string")
        
        if not issubclass(actor_class, NetworkActor):
            raise TypeError(f"Actor class must be a subclass of NetworkActor, got {actor_class}")
        
        if actor_type in self._actors:
            logger.warning(f"Overriding existing actor registration for '{actor_type}'")
        
        self._actors[actor_type] = actor_class
        
        # Clear cached instance if it exists
        if actor_type in self._instances:
            del self._instances[actor_type]
        
        logger.debug(f"Registered actor '{actor_type}': {actor_class.__name__}")
    
    def get_actor(self, actor_type: str) -> Optional[NetworkActor]:
        """
        Get an actor instance by type.
        
        Args:
            actor_type: Type of actor to retrieve
            
        Returns:
            NetworkActor instance or None if not found
        """
        self._ensure_initialized()
        
        if actor_type not in self._actors:
            logger.warning(f"Actor type '{actor_type}' not registered")
            return None
        
        # Return cached instance if available
        if actor_type in self._instances:
            return self._instances[actor_type]
        
        # Create new instance
        try:
            actor_class = self._actors[actor_type]
            instance = actor_class()
            self._instances[actor_type] = instance
            logger.debug(f"Created new instance of actor '{actor_type}'")
            return instance
        except Exception as e:
            logger.error(f"Failed to create instance of actor '{actor_type}': {e}")
            return None
    
    def get_all_actors(self) -> List[NetworkActor]:
        """
        Get instances of all registered actors.
        
        Returns:
            List of all NetworkActor instances
        """
        self._ensure_initialized()
        
        actors = []
        for actor_type in self._actors:
            actor = self.get_actor(actor_type)
            if actor:
                actors.append(actor)
        
        return actors
    
    def get_actors_by_category(self, category: ActorCategory) -> List[NetworkActor]:
        """
        Get all actors of a specific category.
        
        Args:
            category: Actor category to filter by
            
        Returns:
            List of NetworkActor instances in the category
        """
        actors = self.get_all_actors()
        return [actor for actor in actors if actor.actor_category == category]
    
    def list_registered_types(self) -> List[str]:
        """
        Get list of all registered actor types.
        
        Returns:
            List of registered actor type strings
        """
        self._ensure_initialized()
        return list(self._actors.keys())
    
    def is_registered(self, actor_type: str) -> bool:
        """
        Check if an actor type is registered.
        
        Args:
            actor_type: Actor type to check
            
        Returns:
            True if registered, False otherwise
        """
        self._ensure_initialized()
        return actor_type in self._actors
    
    def unregister(self, actor_type: str) -> bool:
        """
        Unregister an actor type.
        
        Args:
            actor_type: Actor type to unregister
            
        Returns:
            True if unregistered, False if not found
        """
        if actor_type not in self._actors:
            return False
        
        del self._actors[actor_type]
        
        # Clear cached instance
        if actor_type in self._instances:
            del self._instances[actor_type]
        
        logger.debug(f"Unregistered actor '{actor_type}'")
        return True
    
    def clear(self) -> None:
        """Clear all registered actors and instances."""
        self._actors.clear()
        self._instances.clear()
        self._initialized = False
        logger.debug("Cleared all registered actors")
    
    def get_registry_info(self) -> Dict[str, Any]:
        """
        Get information about the registry state.
        
        Returns:
            Dictionary with registry information
        """
        self._ensure_initialized()
        
        return {
            'registered_types': list(self._actors.keys()),
            'cached_instances': list(self._instances.keys()),
            'total_registered': len(self._actors),
            'total_cached': len(self._instances),
            'categories': {
                category.value: len(self.get_actors_by_category(category))
                for category in ActorCategory
            }
        }


# Global registry instance
_global_registry = ActorRegistry()


def register_actor(actor_type: str, actor_class: Type[NetworkActor]) -> None:
    """
    Register an actor in the global registry.
    
    Args:
        actor_type: Unique identifier for the actor type
        actor_class: NetworkActor class to register
    """
    _global_registry.register(actor_type, actor_class)


def get_actor(actor_type: str) -> Optional[NetworkActor]:
    """
    Get an actor from the global registry.
    
    Args:
        actor_type: Type of actor to retrieve
        
    Returns:
        NetworkActor instance or None if not found
    """
    return _global_registry.get_actor(actor_type)


def get_all_actors() -> List[NetworkActor]:
    """
    Get all actors from the global registry.
    
    Returns:
        List of all NetworkActor instances
    """
    return _global_registry.get_all_actors()


def get_actors_by_category(category: ActorCategory) -> List[NetworkActor]:
    """
    Get actors by category from the global registry.
    
    Args:
        category: Actor category to filter by
        
    Returns:
        List of NetworkActor instances in the category
    """
    return _global_registry.get_actors_by_category(category)


def list_registered_types() -> List[str]:
    """
    Get list of registered actor types from the global registry.
    
    Returns:
        List of registered actor type strings
    """
    return _global_registry.list_registered_types()


def get_registry() -> ActorRegistry:
    """
    Get the global actor registry instance.
    
    Returns:
        Global ActorRegistry instance
    """
    return _global_registry
