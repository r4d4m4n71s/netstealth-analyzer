"""
Abstract interfaces and contracts for NetStealth Analyzer components.

This module defines the core interfaces that establish contracts for parsers,
detectors, plugins, and other pluggable components in the analysis pipeline.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import asyncio
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import (
    Any, Dict, List, Optional, Union, AsyncIterator, Iterator,
    Protocol, runtime_checkable, TypeVar, Generic, Callable
)
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4
from pathlib import Path

from ..compatibility import override

# Type variables for generic interfaces
T = TypeVar('T')
TResult = TypeVar('TResult')
TConfig = TypeVar('TConfig')


class ComponentStatus(Enum):
    """Status of a component during its lifecycle."""
    
    UNINITIALIZED = "uninitialized"    # Component not yet initialized
    INITIALIZING = "initializing"      # Component is being initialized
    READY = "ready"                    # Component ready for use
    RUNNING = "running"                # Component is actively processing
    PAUSED = "paused"                  # Component is paused
    STOPPING = "stopping"              # Component is being stopped
    STOPPED = "stopped"                # Component has stopped
    ERROR = "error"                    # Component is in error state
    DISPOSED = "disposed"              # Component has been disposed


class Priority(Enum):
    """Priority levels for components and operations."""
    
    LOWEST = 0
    LOW = 25
    NORMAL = 50
    HIGH = 75
    HIGHEST = 100


@dataclass(frozen=True)
class ComponentMetadata:
    """Metadata for components (parsers, detectors, plugins)."""
    
    name: str
    version: str
    description: str
    author: str = ""
    priority: Priority = Priority.NORMAL
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    supported_formats: List[str] = field(default_factory=list)
    configuration_schema: Optional[Dict[str, Any]] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ProcessingContext:
    """Context information passed to components during processing."""
    
    session_id: UUID = field(default_factory=uuid4)
    correlation_id: Optional[UUID] = None
    configuration: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    file_path: Optional[Path] = None
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    timeout_seconds: Optional[float] = None
    
    def with_correlation(self, correlation_id: UUID) -> 'ProcessingContext':
        """Create a copy with correlation ID set."""
        return ProcessingContext(
            session_id=self.session_id,
            correlation_id=correlation_id,
            configuration=self.configuration,
            metadata=self.metadata,
            file_path=self.file_path,
            start_time=self.start_time,
            timeout_seconds=self.timeout_seconds
        )


@dataclass
class ProcessingResult(Generic[T]):
    """Result of a processing operation."""
    
    success: bool
    data: Optional[T] = None
    error: Optional[Exception] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    processing_time_ms: Optional[int] = None
    items_processed: int = 0
    
    @property
    def has_warnings(self) -> bool:
        """Check if result has warnings."""
        return len(self.warnings) > 0
    
    def add_warning(self, message: str) -> None:
        """Add a warning message."""
        self.warnings.append(message)


# ============================================================================
# Core Component Interface
# ============================================================================

class IComponent(ABC):
    """
    Base interface for all components in the NetStealth Analyzer.
    
    Provides lifecycle management, status tracking, and basic operations
    that all components should support.
    """
    
    @property
    @abstractmethod
    def metadata(self) -> ComponentMetadata:
        """Get component metadata."""
        pass
    
    @property
    @abstractmethod
    def status(self) -> ComponentStatus:
        """Get current component status."""
        pass
    
    @abstractmethod
    async def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the component with optional configuration.
        
        Args:
            config: Optional configuration dictionary
            
        Raises:
            ConfigurationError: If configuration is invalid
            InitializationError: If initialization fails
        """
        pass
    
    @abstractmethod
    async def shutdown(self) -> None:
        """
        Shutdown the component gracefully.
        
        Should clean up resources and stop any background tasks.
        """
        pass
    
    @abstractmethod
    def validate_configuration(self, config: Dict[str, Any]) -> bool:
        """
        Validate configuration before initialization.
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if configuration is valid
            
        Raises:
            ValidationError: If configuration is invalid
        """
        pass
    
    @abstractmethod
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get component health status for monitoring.
        
        Returns:
            Dictionary with health information
        """
        pass


# ============================================================================
# Parser Interfaces
# ============================================================================

@runtime_checkable
class ILogParser(Protocol):
    """
    Interface for log file parsers.
    
    Parsers are responsible for reading and parsing different types of log files
    (HAR, mitmproxy, browser console, etc.) into structured data.
    """
    
    @abstractmethod
    async def parse(
        self,
        file_path: Path,
        context: ProcessingContext
    ) -> ProcessingResult[List[Dict[str, Any]]]:
        """
        Parse a log file and return structured data.
        
        Args:
            file_path: Path to the log file
            context: Processing context
            
        Returns:
            ProcessingResult containing parsed log entries
        """
        pass
    
    @abstractmethod
    async def parse_stream(
        self,
        file_path: Path,
        context: ProcessingContext
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Parse a log file as a stream for large files.
        
        Args:
            file_path: Path to the log file
            context: Processing context
            
        Yields:
            Individual parsed log entries
        """
        pass
    
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the given file.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if parser can handle this file
        """
        pass
    
    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        """
        Get list of supported file extensions.
        
        Returns:
            List of file extensions (e.g., ['.har', '.json'])
        """
        pass
    
    @abstractmethod
    async def validate_file(self, file_path: Path) -> bool:
        """
        Validate that a file has the expected format.
        
        Args:
            file_path: Path to validate
            
        Returns:
            True if file format is valid
        """
        pass


class IStreamingParser(Protocol):
    """
    Extended interface for parsers that support real-time streaming.
    
    Useful for parsing logs that are being actively written to.
    """
    
    @abstractmethod
    async def parse_live_stream(
        self,
        file_path: Path,
        context: ProcessingContext,
        poll_interval: float = 1.0
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Parse a log file that is being actively written to.
        
        Args:
            file_path: Path to the log file
            context: Processing context
            poll_interval: How often to check for new data (seconds)
            
        Yields:
            New log entries as they are written
        """
        pass


# ============================================================================
# Detector Interfaces
# ============================================================================

@dataclass
class DetectionResult:
    """Result of a detection operation."""
    
    issues_found: List[Dict[str, Any]]
    confidence_scores: Dict[str, float]
    processing_stats: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class IDetector(Protocol):
    """
    Interface for security issue detectors.
    
    Detectors analyze parsed log data to identify potential security issues,
    misconfigurations, or privacy leaks.
    """
    
    @abstractmethod
    async def detect(
        self,
        log_entries: List[Dict[str, Any]],
        context: ProcessingContext
    ) -> DetectionResult:
        """
        Analyze log entries and detect security issues.
        
        Args:
            log_entries: Parsed log entries to analyze
            context: Processing context
            
        Returns:
            DetectionResult with found issues
        """
        pass
    
    @abstractmethod
    async def detect_streaming(
        self,
        log_stream: AsyncIterator[Dict[str, Any]],
        context: ProcessingContext
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Analyze log entries from a stream and yield issues as found.
        
        Args:
            log_stream: Stream of log entries
            context: Processing context
            
        Yields:
            Security issues as they are detected
        """
        pass
    
    @abstractmethod
    def get_detection_categories(self) -> List[str]:
        """
        Get list of issue categories this detector can find.
        
        Returns:
            List of category names (e.g., ['tls_fingerprint', 'proxy_leak'])
        """
        pass
    
    @abstractmethod
    def get_confidence_threshold(self) -> float:
        """
        Get minimum confidence threshold for reporting issues.
        
        Returns:
            Confidence threshold (0.0 to 1.0)
        """
        pass
    
    @abstractmethod
    def set_confidence_threshold(self, threshold: float) -> None:
        """
        Set minimum confidence threshold for reporting issues.
        
        Args:
            threshold: New threshold (0.0 to 1.0)
        """
        pass


class IBatchDetector(IDetector, Protocol):
    """
    Extended interface for detectors that work better with batch processing.
    
    Some detectors need to analyze multiple log entries together to identify
    patterns or correlations.
    """
    
    @abstractmethod
    async def detect_batch(
        self,
        log_batches: List[List[Dict[str, Any]]],
        context: ProcessingContext
    ) -> DetectionResult:
        """
        Analyze multiple batches of log entries together.
        
        Args:
            log_batches: List of log entry batches
            context: Processing context
            
        Returns:
            DetectionResult with found issues
        """
        pass
    
    @abstractmethod
    def get_optimal_batch_size(self) -> int:
        """
        Get optimal batch size for this detector.
        
        Returns:
            Recommended batch size
        """
        pass


# ============================================================================
# Plugin Interfaces
# ============================================================================

class PluginType(Enum):
    """Types of plugins supported by the system."""
    
    PARSER = "parser"          # Log parser plugin
    DETECTOR = "detector"      # Issue detector plugin
    FORMATTER = "formatter"    # Report formatter plugin
    EXPORTER = "exporter"      # Data exporter plugin
    FILTER = "filter"          # Data filter plugin
    TRANSFORMER = "transformer" # Data transformer plugin


@dataclass(frozen=True)
class PluginMetadata(ComponentMetadata):
    """Extended metadata for plugins."""
    
    plugin_type: PluginType = PluginType.PARSER
    entry_point: str = ""
    min_analyzer_version: str = "2.0.0"
    max_analyzer_version: Optional[str] = None
    license: str = ""
    homepage: str = ""
    
    def is_compatible(self, analyzer_version: str) -> bool:
        """Check if plugin is compatible with analyzer version."""
        # Simplified version check - in real implementation would use semver
        return True  # TODO: Implement proper version checking


@runtime_checkable
class IPlugin(Protocol):
    """
    Base interface for all plugins.
    
    Plugins extend the functionality of the analyzer with custom parsers,
    detectors, formatters, and other components.
    """
    
    @property
    @abstractmethod
    def plugin_metadata(self) -> PluginMetadata:
        """Get plugin-specific metadata."""
        pass
    
    @abstractmethod
    async def load(self) -> None:
        """
        Load the plugin and prepare it for use.
        
        Raises:
            PluginLoadError: If plugin cannot be loaded
        """
        pass
    
    @abstractmethod
    async def unload(self) -> None:
        """
        Unload the plugin and clean up resources.
        """
        pass
    
    @abstractmethod
    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get plugin capabilities and features.
        
        Returns:
            Dictionary describing plugin capabilities
        """
        pass


class IParserPlugin(IPlugin, ILogParser, Protocol):
    """Interface for parser plugins."""
    pass


class IDetectorPlugin(IPlugin, IDetector, Protocol):
    """Interface for detector plugins."""
    pass


# ============================================================================
# Reporter Interfaces
# ============================================================================

class ReportFormat(Enum):
    """Supported report formats."""
    
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    YAML = "yaml"
    CSV = "csv"
    PDF = "pdf"


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    
    format: ReportFormat
    output_path: Optional[Path] = None
    template: Optional[str] = None
    include_raw_data: bool = False
    include_statistics: bool = True
    severity_filter: Optional[List[str]] = None
    category_filter: Optional[List[str]] = None
    custom_fields: Dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class IReporter(Protocol):
    """
    Interface for report generators.
    
    Reporters take analysis results and generate reports in various formats.
    """
    
    @abstractmethod
    async def generate_report(
        self,
        analysis_results: Dict[str, Any],
        config: ReportConfig,
        context: ProcessingContext
    ) -> ProcessingResult[str]:
        """
        Generate a report from analysis results.
        
        Args:
            analysis_results: Results from analysis pipeline
            config: Report configuration
            context: Processing context
            
        Returns:
            ProcessingResult with generated report content
        """
        pass
    
    @abstractmethod
    async def generate_streaming_report(
        self,
        results_stream: AsyncIterator[Dict[str, Any]],
        config: ReportConfig,
        context: ProcessingContext
    ) -> AsyncIterator[str]:
        """
        Generate a report from streaming results.
        
        Args:
            results_stream: Stream of analysis results
            config: Report configuration
            context: Processing context
            
        Yields:
            Report chunks as they are generated
        """
        pass
    
    @abstractmethod
    def get_supported_formats(self) -> List[ReportFormat]:
        """
        Get list of supported report formats.
        
        Returns:
            List of supported formats
        """
        pass
    
    @abstractmethod
    def validate_config(self, config: ReportConfig) -> bool:
        """
        Validate report configuration.
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if configuration is valid
        """
        pass


# ============================================================================
# Pipeline Interfaces
# ============================================================================

@dataclass
class PipelineStage:
    """Definition of a pipeline stage."""
    
    name: str
    component: IComponent
    depends_on: List[str] = field(default_factory=list)
    parallel: bool = False
    optional: bool = False
    timeout_seconds: Optional[float] = None
    retry_count: int = 0


@runtime_checkable
class IPipeline(Protocol):
    """
    Interface for analysis pipelines.
    
    Pipelines orchestrate the execution of parsers, detectors, and reporters
    in a coordinated workflow.
    """
    
    @abstractmethod
    async def add_stage(self, stage: PipelineStage) -> None:
        """
        Add a stage to the pipeline.
        
        Args:
            stage: Stage to add
        """
        pass
    
    @abstractmethod
    async def remove_stage(self, stage_name: str) -> bool:
        """
        Remove a stage from the pipeline.
        
        Args:
            stage_name: Name of stage to remove
            
        Returns:
            True if stage was removed
        """
        pass
    
    @abstractmethod
    async def execute(
        self,
        input_data: Any,
        context: ProcessingContext
    ) -> ProcessingResult[Dict[str, Any]]:
        """
        Execute the pipeline with input data.
        
        Args:
            input_data: Input data for pipeline
            context: Processing context
            
        Returns:
            ProcessingResult with pipeline output
        """
        pass
    
    @abstractmethod
    async def execute_streaming(
        self,
        input_stream: AsyncIterator[Any],
        context: ProcessingContext
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Execute the pipeline with streaming input.
        
        Args:
            input_stream: Stream of input data
            context: Processing context
            
        Yields:
            Pipeline results as they are produced
        """
        pass
    
    @abstractmethod
    def get_stage_order(self) -> List[str]:
        """
        Get the execution order of pipeline stages.
        
        Returns:
            List of stage names in execution order
        """
        pass
    
    @abstractmethod
    def validate_pipeline(self) -> bool:
        """
        Validate that the pipeline configuration is correct.
        
        Returns:
            True if pipeline is valid
        """
        pass


# ============================================================================
# Registry Interfaces
# ============================================================================

@runtime_checkable
class IRegistry(Protocol[T]):
    """
    Generic interface for component registries.
    
    Registries manage the discovery, loading, and lifecycle of components.
    """
    
    @abstractmethod
    async def register(self, name: str, component: T) -> None:
        """
        Register a component.
        
        Args:
            name: Component name
            component: Component instance
        """
        pass
    
    @abstractmethod
    async def unregister(self, name: str) -> bool:
        """
        Unregister a component.
        
        Args:
            name: Component name
            
        Returns:
            True if component was unregistered
        """
        pass
    
    @abstractmethod
    def get(self, name: str) -> Optional[T]:
        """
        Get a registered component.
        
        Args:
            name: Component name
            
        Returns:
            Component instance or None
        """
        pass
    
    @abstractmethod
    def list_all(self) -> Dict[str, T]:
        """
        Get all registered components.
        
        Returns:
            Dictionary of name -> component
        """
        pass
    
    @abstractmethod
    def find_by_type(self, component_type: type) -> List[T]:
        """
        Find components by type.
        
        Args:
            component_type: Type to search for
            
        Returns:
            List of matching components
        """
        pass
    
    @abstractmethod
    async def discover_components(self, search_paths: List[Path]) -> int:
        """
        Discover and register components from search paths.
        
        Args:
            search_paths: Paths to search for components
            
        Returns:
            Number of components discovered
        """
        pass


# ============================================================================
# Configuration Interface
# ============================================================================

@runtime_checkable
class IConfigurable(Protocol):
    """
    Interface for components that can be configured.
    """
    
    @abstractmethod
    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure the component.
        
        Args:
            config: Configuration dictionary
        """
        pass
    
    @abstractmethod
    def get_configuration(self) -> Dict[str, Any]:
        """
        Get current configuration.
        
        Returns:
            Current configuration dictionary
        """
        pass
    
    @abstractmethod
    def get_configuration_schema(self) -> Dict[str, Any]:
        """
        Get configuration schema for validation.
        
        Returns:
            JSON schema for configuration
        """
        pass


# Export public API
__all__ = [
    # Enums
    'ComponentStatus',
    'Priority',
    'PluginType',
    'ReportFormat',
    
    # Data classes
    'ComponentMetadata',
    'ProcessingContext',
    'ProcessingResult',
    'DetectionResult',
    'PluginMetadata',
    'ReportConfig',
    'PipelineStage',
    
    # Core interfaces
    'IComponent',
    'IConfigurable',
    
    # Parser interfaces
    'ILogParser',
    'IStreamingParser',
    
    # Detector interfaces
    'IDetector',
    'IBatchDetector',
    
    # Plugin interfaces
    'IPlugin',
    'IParserPlugin',
    'IDetectorPlugin',
    
    # Reporter interfaces
    'IReporter',
    
    # Pipeline interfaces
    'IPipeline',
    
    # Registry interfaces
    'IRegistry',
]
