"""
Plugin system for NetStealth Analyzer.

This module provides a comprehensive plugin architecture that allows for dynamic loading
of custom detectors, parsers, and other components with sandboxing and registry management.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.13+
"""

from .base import (
    IPlugin,
    IDetectorPlugin,
    IParserPlugin,
    IFormatterPlugin,
    PluginMetadata,
    PluginType,
    PluginStatus
)
from .registry import PluginRegistry
from .loader import PluginLoader
from .sandbox import PluginSandbox

__all__ = [
    'IPlugin',
    'IDetectorPlugin',
    'IParserPlugin',
    'IFormatterPlugin',
    'PluginMetadata',
    'PluginType',
    'PluginStatus',
    'PluginRegistry',
    'PluginLoader',
    'PluginSandbox',
]
