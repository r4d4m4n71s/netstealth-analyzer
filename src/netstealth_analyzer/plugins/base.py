"""
Base plugin interfaces and metadata for NetStealth Analyzer.

This module defines the core plugin architecture including abstract base classes,
metadata structures, and plugin types with full async support.
"""

import asyncio
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone
from dataclasses import dataclass, field

from ..models.issues import Issue
from ..models.network import NetworkTrace
from ..detectors.base import DetectionContext, DetectionResult
from ..parsers.base import ParseResult
from ..reporting.formats import ReportFormatter


class PluginType(Enum):
    """Plugin type enumeration."""
    DETECTOR = "detector"
    PARSER = "parser"
    FORMATTER = "formatter"
    ANALYZER = "analyzer"
    UTILITY = "utility"


class PluginStatus(Enum):
    """Plugin status enumeration."""
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass
class PluginMetadata:
    """
    Plugin metadata containing information about the plugin.
    
    This class holds all the essential information about a plugin including
    its identity, capabilities, dependencies, and configuration.
    """
    
    # Basic identification
    name: str
    version: str
    plugin_type: PluginType
    description: str = ""
    author: str = ""
    
    # Compatibility and requirements
    min_analyzer_version: str = "2.0.0"
    max_analyzer_version: str = ""
    python_version: str = "3.13+"
    dependencies: List[str] = field(default_factory=list)
    
    # Plugin capabilities
    supported_formats: List[str] = field(default_factory=list)
    supported_categories: List[str] = field(default_factory=list)
    
    # Configuration and behavior
    config_schema: Dict[str, Any] = field(default_factory=dict)
    default_config: Dict[str, Any] = field(default_factory=dict)
    sandboxed: bool = True
    async_capable: bool = True
    
    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: List[str] = field(default_factory=list)
    homepage: str = ""
    documentation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        return {
            'name': self.name,
            'version': self.version,
            'plugin_type': self.plugin_type.value,
            'description': self.description,
            'author': self.author,
            'min_analyzer_version': self.min_analyzer_version,
            'max_analyzer_version': self.max_analyzer_version,
            'python_version': self.python_version,
            'dependencies': self.dependencies,
            'supported_formats': self.supported_formats,
            'supported_categories': self.supported_categories,
            'config_schema': self.config_schema,
            'default_config': self.default_config,
            'sandboxed': self.sandboxed,
            'async_capable': self.async_capable,
            'created_at': self.created_at.isoformat(),
            'tags': self.tags,
            'homepage': self.homepage,
            'documentation': self.documentation
        }


class IPlugin(ABC):
    """
    Abstract base class for all plugins.
    
    This interface defines the core functionality that all plugins must implement,
    including initialization, configuration, and lifecycle management.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize plugin with optional configuration."""
        self.config = config or {}
        self.status = PluginStatus.UNLOADED
        self._initialized = False
    
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        pass
    
    @property
    def name(self) -> str:
        """Get plugin name."""
        return self.metadata.name
    
    @property
    def version(self) -> str:
        """Get plugin version."""
        return self.metadata.version
    
    @property
    def plugin_type(self) -> PluginType:
        """Get plugin type."""
        return self.metadata.plugin_type
    
    @property
    def is_initialized(self) -> bool:
        """Check if plugin is initialized."""
        return self._initialized
    
    async def initialize(self) -> None:
        """
        Initialize the plugin.
        
        This method is called when the plugin is loaded and should perform
        any necessary setup operations.
        """
        self.status = PluginStatus.LOADING
        try:
            await self._initialize_impl()
            self._initialized = True
            self.status = PluginStatus.LOADED
        except Exception as e:
            self.status = PluginStatus.ERROR
            raise RuntimeError(f"Failed to initialize plugin {self.name}: {e}")
    
    async def _initialize_impl(self) -> None:
        """
        Plugin-specific initialization implementation.
        
        Override this method to provide custom initialization logic.
        """
        pass
    
    async def cleanup(self) -> None:
        """
        Clean up plugin resources.
        
        This method is called when the plugin is unloaded and should perform
        any necessary cleanup operations.
        """
        try:
            await self._cleanup_impl()
            self._initialized = False
            self.status = PluginStatus.UNLOADED
        except Exception as e:
            self.status = PluginStatus.ERROR
            raise RuntimeError(f"Failed to cleanup plugin {self.name}: {e}")
    
    async def _cleanup_impl(self) -> None:
        """
        Plugin-specific cleanup implementation.
        
        Override this method to provide custom cleanup logic.
        """
        pass
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate plugin configuration.
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            True if configuration is valid, False otherwise
        """
        # Basic validation against schema if provided
        schema = self.metadata.config_schema
        if not schema:
            return True
        
        # Simple validation - can be enhanced with jsonschema
        for key, spec in schema.items():
            if spec.get('required', False) and key not in config:
                return False
            
            if key in config:
                expected_type = spec.get('type')
                if expected_type and not isinstance(config[key], expected_type):
                    return False
        
        return True
    
    def get_config_value(self, key: str, default: Any = None) -> Any:
        """Get configuration value with fallback to default."""
        return self.config.get(key, self.metadata.default_config.get(key, default))


class IDetectorPlugin(IPlugin):
    """
    Abstract base class for detector plugins.
    
    Detector plugins implement custom issue detection logic that can be
    dynamically loaded and integrated into the analysis pipeline.
    """
    
    @property
    def plugin_type(self) -> PluginType:
        """Get plugin type."""
        return PluginType.DETECTOR
    
    @abstractmethod
    async def detect(self, context: DetectionContext) -> DetectionResult:
        """
        Perform detection on the provided context.
        
        Args:
            context: Detection context with traces and configuration
            
        Returns:
            DetectionResult with found issues and statistics
        """
        pass
    
    def get_supported_categories(self) -> List[str]:
        """Get list of issue categories this detector can identify."""
        return self.metadata.supported_categories
    
    def get_confidence_threshold(self) -> float:
        """Get confidence threshold for this detector."""
        return self.get_config_value('confidence_threshold', 0.7)


class IParserPlugin(IPlugin):
    """
    Abstract base class for parser plugins.
    
    Parser plugins implement custom log parsing logic for different
    log formats and data sources.
    """
    
    @property
    def plugin_type(self) -> PluginType:
        """Get plugin type."""
        return PluginType.PARSER
    
    @abstractmethod
    async def parse(self, file_path: str, **kwargs) -> ParseResult:
        """
        Parse logs from the provided file path.
        
        Args:
            file_path: Path to the log file to parse
            **kwargs: Additional parsing configuration
            
        Returns:
            ParseResult with extracted network traces
        """
        pass
    
    @abstractmethod
    def can_parse(self, file_path: str, content_sample: str) -> bool:
        """
        Check if this parser can handle the given file.
        
        Args:
            file_path: Path to the log file
            content_sample: Sample of file content for format detection
            
        Returns:
            True if this parser can handle the file, False otherwise
        """
        pass
    
    def get_supported_formats(self) -> List[str]:
        """Get list of log formats this parser supports."""
        return self.metadata.supported_formats
    
    def get_file_extensions(self) -> List[str]:
        """Get list of file extensions this parser supports."""
        return self.get_config_value('file_extensions', [])


class IFormatterPlugin(IPlugin):
    """
    Abstract base class for formatter plugins.
    
    Formatter plugins implement custom report formatting logic for
    different output formats and presentation styles.
    """
    
    @property
    def plugin_type(self) -> PluginType:
        """Get plugin type."""
        return PluginType.FORMATTER
    
    @abstractmethod
    def format(self, report: 'Report') -> str:
        """
        Format the report into the target format.
        
        Args:
            report: Report object to format
            
        Returns:
            Formatted report as string
        """
        pass
    
    def get_output_format(self) -> str:
        """Get the output format name."""
        return self.get_config_value('output_format', 'custom')
    
    def get_file_extension(self) -> str:
        """Get the recommended file extension for this format."""
        return self.get_config_value('file_extension', '.txt')
    
    def supports_streaming(self) -> bool:
        """Check if this formatter supports streaming output."""
        return self.get_config_value('supports_streaming', False)


class PluginError(Exception):
    """Base exception for plugin-related errors."""
    
    def __init__(self, message: str, plugin_name: str = "", cause: Optional[Exception] = None):
        """Initialize plugin error."""
        super().__init__(message)
        self.plugin_name = plugin_name
        self.cause = cause


class PluginLoadError(PluginError):
    """Exception raised when a plugin fails to load."""
    pass


class PluginInitializationError(PluginError):
    """Exception raised when a plugin fails to initialize."""
    pass


class PluginExecutionError(PluginError):
    """Exception raised when a plugin fails during execution."""
    pass


class PluginValidationError(PluginError):
    """Exception raised when plugin validation fails."""
    pass
