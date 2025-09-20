"""
Network Actor Detection System.

This module provides a hierarchical, extensible system for identifying and analyzing
network entities in the request path. It moves beyond simple proxy detection to
comprehensive network actor identification and behavioral analysis.

Author: NetStealth Analyzer Team
Version: 1.0.0
Python: 3.13+
"""

from .base import (
    NetworkActor,
    ActorIdentification,
    BehaviorAnalysis,
    ActorPattern,
    HeaderPattern,
    IPRangePattern,
    ResponsePattern,
    PortPattern
)
from .registry import ActorRegistry, register_actor, get_actor
from .proxy import ProxyActor

# Export all public classes and functions
__all__ = [
    # Base classes
    'NetworkActor',
    'ActorIdentification',
    'BehaviorAnalysis',
    
    # Pattern classes
    'ActorPattern',
    'HeaderPattern',
    'IPRangePattern',
    'ResponsePattern',
    'PortPattern',
    
    # Registry
    'ActorRegistry',
    'register_actor',
    'get_actor',
    
    # Implemented actors
    'ProxyActor',
]

# Version information
__version__ = "1.0.0"
__author__ = "NetStealth Analyzer Team"
