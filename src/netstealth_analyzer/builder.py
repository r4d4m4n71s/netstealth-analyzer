"""
Fluent API builder for NetStealth Analyzer.

This module provides a fluent interface for configuring and building
analyzer instances with method chaining and comprehensive validation.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import asyncio
from typing import Any, Dict, List, Optional, Union, Callable, AsyncIterator
from pathlib import Path
from datetime import datetime, timezone

from .config import NetStealthConfig, get_config_manager
from .core.events import EventBus, AnalysisEvent, get_event_bus
from .core.errors import ConfigurationError, ValidationError, ErrorContext
from .core.interfaces import IComponent, ILogParser, IDetector, IReporter, ProcessingContext
from .detectors.registry import get_global_registry
from .models.enums import LogFormat, AnalysisStatus
from .models.results import AnalysisResult, ExecutionContext
from .compatibility import override

import logging

logger = logging.getLogger(__name__)


class AnalyzerBuilder:
    """
    Fluent API builder for creating NetStealth Analyzer instances.
    
    Provides method chaining for intuitive configuration and validation
    before building the final analyzer instance.
    """
    
    def __init__(self):
        # Core configuration
        self._config = NetStealthConfig()
        self._event_bus: Optional[EventBus] = None
        
        # Input sources
        self._log_files: List[Path] = []
        self._log_formats: Dict[Path, LogFormat] = {}
        
        # Analysis configuration
        self._target_service: Optional[str] = None
        self._geography: Optional[str] = None
        self._custom_rules: List[Dict[str, Any]] = []
        
        # Components
        self._parsers: List[ILogParser] = []
        self._detectors: List[IDetector] = []
        self._reporters: List[IReporter] = []
        self._plugins: List[IComponent] = []
        
        # Event handlers
        self._event_handlers: Dict[AnalysisEvent, List[Callable]] = {}
        self._progress_callback: Optional[Callable] = None
        
        # Advanced options
        self._enable_streaming: bool = False
        self._enable_fingerprint_analysis: bool = False
        self._enable_session_timeline: bool = False
        self._enable_diff_analysis: bool = False
        
        # Output configuration
        self._output_formats: List[str] = ["json"]
        self._output_directory: Optional[Path] = None
        self._include_raw_data: bool = False
        
        # Performance settings
        self._max_concurrent_parsers: Optional[int] = None
        self._timeout_seconds: Optional[float] = None
        self._memory_limit_mb: Optional[int] = None
    
    # ========================================================================
    # Input Configuration
    # ========================================================================
    
    def with_log(
        self, 
        file_path: Union[str, Path], 
        format: Optional[LogFormat] = None
    ) -> 'AnalyzerBuilder':
        """
        Add a single log file to analyze.
        
        Args:
            file_path: Path to the log file
            format: Log format (auto-detected if not specified)
            
        Returns:
            Self for method chaining
        """
        path = Path(file_path)
        
        if not path.exists():
            raise ConfigurationError(f"Log file not found: {path}")
        
        self._log_files.append(path)
        
        if format:
            self._log_formats[path] = format
        else:
            # Auto-detect format based on file extension
            detected_format = self._detect_log_format(path)
            if detected_format:
                self._log_formats[path] = detected_format
        
        logger.debug(f"Added log file: {path} (format: {format or 'auto-detect'})")
        return self
    
    def with_logs(self, *file_paths: Union[str, Path]) -> 'AnalyzerBuilder':
        """
        Add multiple log files to analyze.
        
        Args:
            *file_paths: Variable number of file paths
            
        Returns:
            Self for method chaining
        """
        for file_path in file_paths:
            self.with_log(file_path)
        return self
    
    def with_log_directory(
        self, 
        directory: Union[str, Path], 
        pattern: str = "*",
        recursive: bool = False
    ) -> 'AnalyzerBuilder':
        """
        Add all log files from a directory.
        
        Args:
            directory: Directory containing log files
            pattern: File pattern to match (default: "*")
            recursive: Whether to search recursively
            
        Returns:
            Self for method chaining
        """
        dir_path = Path(directory)
        
        if not dir_path.exists() or not dir_path.is_dir():
            raise ConfigurationError(f"Directory not found: {dir_path}")
        
        if recursive:
            files = dir_path.rglob(pattern)
        else:
            files = dir_path.glob(pattern)
        
        for file_path in files:
            if file_path.is_file():
                self.with_log(file_path)
        
        logger.debug(f"Added log directory: {dir_path} (pattern: {pattern}, recursive: {recursive})")
        return self
    
    def _detect_log_format(self, file_path: Path) -> Optional[LogFormat]:
        """Auto-detect log format based on file extension."""
        extension = file_path.suffix.lower()
        
        format_mapping = {
            '.har': LogFormat.HAR,
            '.mitm': LogFormat.MITMPROXY,
            '.flow': LogFormat.MITMPROXY,
            '.json': LogFormat.JSON_LINES,
            '.jsonl': LogFormat.JSON_LINES,
            '.ndjson': LogFormat.JSON_LINES,
            '.csv': LogFormat.CSV,
            '.log': LogFormat.PLAIN_TEXT,
            '.txt': LogFormat.PLAIN_TEXT,
        }
        
        return format_mapping.get(extension)
    
    # ========================================================================
    # Target Configuration
    # ========================================================================
    
    def for_service(self, service_domain: str) -> 'AnalyzerBuilder':
        """
        Set the target service domain for analysis.
        
        Args:
            service_domain: Domain name of the target service
            
        Returns:
            Self for method chaining
        """
        if not service_domain or not isinstance(service_domain, str):
            raise ConfigurationError("Service domain must be a non-empty string")
        
        self._target_service = service_domain
        self._config.target_service = service_domain
        
        logger.debug(f"Set target service: {service_domain}")
        return self
    
    def in_geography(self, country_code: str) -> 'AnalyzerBuilder':
        """
        Set the expected geographic location.
        
        Args:
            country_code: ISO country code (e.g., 'US', 'UK', 'DE')
            
        Returns:
            Self for method chaining
        """
        if not country_code or len(country_code) != 2:
            raise ConfigurationError("Country code must be a 2-letter ISO code")
        
        self._geography = country_code.upper()
        self._config.geography = self._geography
        
        logger.debug(f"Set geography: {self._geography}")
        return self
    
    # ========================================================================
    # Feature Configuration
    # ========================================================================
    
    def enable_streaming(self) -> 'AnalyzerBuilder':
        """
        Enable streaming analysis for real-time results.
        
        Returns:
            Self for method chaining
        """
        self._enable_streaming = True
        logger.debug("Enabled streaming analysis")
        return self
    
    def enable_fingerprint_analysis(self) -> 'AnalyzerBuilder':
        """
        Enable detailed fingerprint analysis.
        
        Returns:
            Self for method chaining
        """
        self._enable_fingerprint_analysis = True
        logger.debug("Enabled fingerprint analysis")
        return self
    
    def enable_session_timeline(self) -> 'AnalyzerBuilder':
        """
        Enable session timeline generation.
        
        Returns:
            Self for method chaining
        """
        self._enable_session_timeline = True
        logger.debug("Enabled session timeline")
        return self
    
    def enable_diff_analysis(self) -> 'AnalyzerBuilder':
        """
        Enable differential analysis between sessions.
        
        Returns:
            Self for method chaining
        """
        self._enable_diff_analysis = True
        logger.debug("Enabled diff analysis")
        return self
    
    # ========================================================================
    # Component Configuration
    # ========================================================================
    
    def with_parser(self, parser: ILogParser) -> 'AnalyzerBuilder':
        """
        Add a custom parser component.
        
        Args:
            parser: Parser component implementing ILogParser
            
        Returns:
            Self for method chaining
        """
        if not hasattr(parser, 'parse'):
            raise ConfigurationError("Parser must implement ILogParser interface")
        
        self._parsers.append(parser)
        logger.debug(f"Added parser: {type(parser).__name__}")
        return self
    
    def with_detector(self, detector: IDetector) -> 'AnalyzerBuilder':
        """
        Add a custom detector component.
        
        Args:
            detector: Detector component implementing IDetector
            
        Returns:
            Self for method chaining
        """
        if not hasattr(detector, 'detect'):
            raise ConfigurationError("Detector must implement IDetector interface")
        
        self._detectors.append(detector)
        logger.debug(f"Added detector: {type(detector).__name__}")
        return self
    
    def with_detectors(self, *detector_names: str) -> 'AnalyzerBuilder':
        """
        Add multiple detectors by name from the global registry.
        
        Args:
            *detector_names: Names of detectors to add
            
        Returns:
            Self for method chaining
        """
        registry = get_global_registry()
        
        for detector_name in detector_names:
            detector = registry.create_detector(detector_name)
            if detector:
                self.with_detector(detector)
                logger.debug(f"Added detector from registry: {detector_name}")
            else:
                logger.warning(f"Detector not found or disabled: {detector_name}")
        
        return self
    
    def with_reporter(self, reporter: IReporter) -> 'AnalyzerBuilder':
        """
        Add a custom reporter component.
        
        Args:
            reporter: Reporter component implementing IReporter
            
        Returns:
            Self for method chaining
        """
        if not hasattr(reporter, 'generate_report'):
            raise ConfigurationError("Reporter must implement IReporter interface")
        
        self._reporters.append(reporter)
        logger.debug(f"Added reporter: {type(reporter).__name__}")
        return self
    
    def with_plugin(self, plugin: IComponent) -> 'AnalyzerBuilder':
        """
        Add a plugin component.
        
        Args:
            plugin: Plugin component implementing IComponent
            
        Returns:
            Self for method chaining
        """
        if not hasattr(plugin, 'metadata'):
            raise ConfigurationError("Plugin must implement IComponent interface")
        
        self._plugins.append(plugin)
        logger.debug(f"Added plugin: {plugin.metadata.name}")
        return self
    
    # ========================================================================
    # Event Configuration
    # ========================================================================
    
    def on(self, event: AnalysisEvent, handler: Callable) -> 'AnalyzerBuilder':
        """
        Register an event handler.
        
        Args:
            event: Event type to listen for
            handler: Callback function to handle the event
            
        Returns:
            Self for method chaining
        """
        if event not in self._event_handlers:
            self._event_handlers[event] = []
        
        self._event_handlers[event].append(handler)
        logger.debug(f"Registered handler for event: {event.value}")
        return self
    
    def track_progress(self, callback: Callable[[int, int, str], None]) -> 'AnalyzerBuilder':
        """
        Set a progress tracking callback.
        
        Args:
            callback: Function called with (current, total, message)
            
        Returns:
            Self for method chaining
        """
        self._progress_callback = callback
        logger.debug("Set progress tracking callback")
        return self
    
    def track_events(self, handler: Callable[[AnalysisEvent, Any], None]) -> 'AnalyzerBuilder':
        """
        Set a general event handler for all events.
        
        Args:
            handler: Function called with (event, data)
            
        Returns:
            Self for method chaining
        """
        # Register for all events
        for event in AnalysisEvent:
            self.on(event, lambda e, d, h=handler: h(e, d))
        
        logger.debug("Set general event handler")
        return self
    
    # ========================================================================
    # Output Configuration
    # ========================================================================
    
    def output_to(self, directory: Union[str, Path]) -> 'AnalyzerBuilder':
        """
        Set output directory for reports.
        
        Args:
            directory: Directory to save reports
            
        Returns:
            Self for method chaining
        """
        self._output_directory = Path(directory)
        self._output_directory.mkdir(parents=True, exist_ok=True)
        
        logger.debug(f"Set output directory: {self._output_directory}")
        return self
    
    def output_formats(self, *formats: str) -> 'AnalyzerBuilder':
        """
        Set output formats for reports.
        
        Args:
            *formats: Report formats (json, markdown, html, yaml)
            
        Returns:
            Self for method chaining
        """
        allowed_formats = {'json', 'markdown', 'html', 'yaml'}
        
        for fmt in formats:
            if fmt not in allowed_formats:
                raise ConfigurationError(f"Unsupported format: {fmt}. Allowed: {allowed_formats}")
        
        self._output_formats = list(formats)
        logger.debug(f"Set output formats: {self._output_formats}")
        return self
    
    def include_raw_data(self, include: bool = True) -> 'AnalyzerBuilder':
        """
        Include raw log data in reports.
        
        Args:
            include: Whether to include raw data
            
        Returns:
            Self for method chaining
        """
        self._include_raw_data = include
        logger.debug(f"Include raw data: {include}")
        return self
    
    # ========================================================================
    # Performance Configuration
    # ========================================================================
    
    def max_concurrent_parsers(self, count: int) -> 'AnalyzerBuilder':
        """
        Set maximum concurrent parsers.
        
        Args:
            count: Maximum number of concurrent parsers
            
        Returns:
            Self for method chaining
        """
        if count < 1:
            raise ConfigurationError("Concurrent parsers count must be >= 1")
        
        self._max_concurrent_parsers = count
        logger.debug(f"Set max concurrent parsers: {count}")
        return self
    
    def timeout(self, seconds: float) -> 'AnalyzerBuilder':
        """
        Set analysis timeout.
        
        Args:
            seconds: Timeout in seconds
            
        Returns:
            Self for method chaining
        """
        if seconds <= 0:
            raise ConfigurationError("Timeout must be positive")
        
        self._timeout_seconds = seconds
        logger.debug(f"Set timeout: {seconds}s")
        return self
    
    def memory_limit(self, mb: int) -> 'AnalyzerBuilder':
        """
        Set memory usage limit.
        
        Args:
            mb: Memory limit in megabytes
            
        Returns:
            Self for method chaining
        """
        if mb < 64:
            raise ConfigurationError("Memory limit must be >= 64MB")
        
        self._memory_limit_mb = mb
        logger.debug(f"Set memory limit: {mb}MB")
        return self
    
    # ========================================================================
    # Configuration Loading
    # ========================================================================
    
    def with_config(self, config: Union[NetStealthConfig, Dict[str, Any], str, Path]) -> 'AnalyzerBuilder':
        """
        Load configuration from various sources.
        
        Args:
            config: Configuration object, dict, or file path
            
        Returns:
            Self for method chaining
        """
        if isinstance(config, NetStealthConfig):
            self._config = config
        elif isinstance(config, dict):
            self._config = NetStealthConfig(**config)
        elif isinstance(config, (str, Path)):
            config_manager = get_config_manager()
            self._config = config_manager.load_from_file(config)
        else:
            raise ConfigurationError(f"Unsupported config type: {type(config)}")
        
        logger.debug("Loaded configuration")
        return self
    
    def with_config_file(self, file_path: Union[str, Path]) -> 'AnalyzerBuilder':
        """
        Load configuration from file.
        
        Args:
            file_path: Path to configuration file
            
        Returns:
            Self for method chaining
        """
        return self.with_config(file_path)
    
    # ========================================================================
    # Validation and Building
    # ========================================================================
    
    def validate(self) -> 'AnalyzerBuilder':
        """
        Validate the current configuration.
        
        Returns:
            Self for method chaining
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        errors = []
        
        # Check required inputs
        if not self._log_files:
            errors.append("No log files specified")
        
        # Validate log files exist
        for log_file in self._log_files:
            if not log_file.exists():
                errors.append(f"Log file not found: {log_file}")
        
        # Check target service if geography is specified
        if self._geography and not self._target_service:
            errors.append("Target service required when geography is specified")
        
        # Validate output directory
        if self._output_directory and not self._output_directory.parent.exists():
            errors.append(f"Output directory parent does not exist: {self._output_directory.parent}")
        
        # Validate performance settings
        if self._max_concurrent_parsers and self._max_concurrent_parsers > 50:
            errors.append("Maximum concurrent parsers should not exceed 50")
        
        if self._timeout_seconds and self._timeout_seconds > 3600:
            errors.append("Timeout should not exceed 1 hour")
        
        if self._memory_limit_mb and self._memory_limit_mb > 8192:
            errors.append("Memory limit should not exceed 8GB")
        
        if errors:
            raise ConfigurationError(f"Configuration validation failed: {'; '.join(errors)}")
        
        logger.debug("Configuration validation passed")
        return self
    
    def build(self) -> 'NetStealthAnalyzer':
        """
        Build the configured analyzer instance.
        
        Returns:
            Configured NetStealth Analyzer instance
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Validate configuration
        self.validate()
        
        # Apply builder settings to config
        self._apply_settings_to_config()
        
        # Create event bus if not provided
        if self._event_bus is None:
            self._event_bus = get_event_bus()
        
        # Register event handlers
        for event, handlers in self._event_handlers.items():
            for handler in handlers:
                self._event_bus.subscribe(event, handler)
        
        # Auto-populate components if none provided
        self._auto_populate_components()
        
        # Create analyzer instance
        from .analyzer import NetStealthAnalyzer
        
        analyzer = NetStealthAnalyzer(
            config=self._config,
            event_bus=self._event_bus,
            log_files=self._log_files,
            log_formats=self._log_formats,
            parsers=self._parsers,
            detectors=self._detectors,
            reporters=self._reporters,
            plugins=self._plugins,
            progress_callback=self._progress_callback
        )
        
        logger.info(f"Built analyzer with {len(self._log_files)} log files and {len(self._plugins)} plugins")
        return analyzer
    
    def _auto_populate_components(self) -> None:
        """Auto-populate components if none were explicitly provided."""
        # Auto-add parsers based on file formats
        if not self._parsers:
            from .parsers.har import HarParser
            from .parsers.mitmproxy import MitmproxyParser
            
            # Add parsers for detected formats
            formats_used = set(self._log_formats.values())
            
            if LogFormat.HAR in formats_used:
                har_parser = HarParser(
                    event_bus=self._event_bus,
                    service_domains=[self._target_service] if self._target_service else []
                )
                self._parsers.append(har_parser)
                logger.debug("Auto-added HAR parser")
            
            if LogFormat.MITMPROXY in formats_used:
                mitm_parser = MitmproxyParser(
                    event_bus=self._event_bus,
                    service_domains=[self._target_service] if self._target_service else []
                )
                self._parsers.append(mitm_parser)
                logger.debug("Auto-added mitmproxy parser")
        
        # Auto-add default detectors if none were explicitly added
        if not self._detectors:
            from .detectors.browser import BrowserDetector
            from .detectors.network import NetworkDetector
            from .detectors.proxy import ProxyDetector
            from .detectors.tls import TlsDetector
            
            # Add core detectors
            self._detectors.extend([
                TlsDetector(event_bus=self._event_bus),
                BrowserDetector(event_bus=self._event_bus),
                NetworkDetector(event_bus=self._event_bus), 
                ProxyDetector(event_bus=self._event_bus)
            ])
            logger.debug("Auto-added core detectors: tls, browser, network, proxy")
    
    def _apply_settings_to_config(self) -> None:
        """Apply builder settings to the configuration object."""
        # Performance settings
        if self._max_concurrent_parsers:
            self._config.performance.max_concurrent_parsers = self._max_concurrent_parsers
        
        if self._timeout_seconds:
            self._config.performance.timeout_seconds = self._timeout_seconds
        
        if self._memory_limit_mb:
            self._config.performance.max_memory_usage_mb = self._memory_limit_mb
        
        # Output settings
        if self._output_directory:
            self._config.output.directory = self._output_directory
        
        self._config.output.include_raw_data = self._include_raw_data
        
        # Feature settings
        if self._enable_fingerprint_analysis:
            self._config.custom['fingerprint_analysis'] = True
        
        if self._enable_session_timeline:
            self._config.custom['session_timeline'] = True
        
        if self._enable_diff_analysis:
            self._config.custom['diff_analysis'] = True
        
        if self._enable_streaming:
            self._config.custom['streaming'] = True


# ========================================================================
# Main Analyzer Class
# ========================================================================

class NetStealthAnalyzer:
    """
    Main NetStealth Analyzer class.
    
    Provides the primary interface for performing security analysis
    with comprehensive configuration and async support.
    """
    
    def __init__(
        self,
        config: NetStealthConfig,
        event_bus: EventBus,
        log_files: List[Path],
        log_formats: Dict[Path, LogFormat],
        parsers: List[ILogParser],
        detectors: List[IDetector],
        reporters: List[IReporter],
        plugins: List[IComponent],
        progress_callback: Optional[Callable] = None
    ):
        self._config = config
        self._event_bus = event_bus
        self._log_files = log_files
        self._log_formats = log_formats
        self._parsers = parsers
        self._detectors = detectors
        self._reporters = reporters
        self._plugins = plugins
        self._progress_callback = progress_callback
        
        # Initialize pipeline
        from .core.pipeline import PipelineEngine
        self._pipeline = PipelineEngine(
            name="netstealth_analyzer",
            event_bus=event_bus
        )
    
    @classmethod
    def create(cls) -> AnalyzerBuilder:
        """
        Create a new analyzer builder for fluent configuration.
        
        Returns:
            New AnalyzerBuilder instance
        """
        return AnalyzerBuilder()
    
    async def analyze(self) -> AnalysisResult:
        """
        Perform complete analysis of configured log files.
        
        Returns:
            Complete analysis results
        """
        # Use direct processing instead of empty pipeline
        return await self._direct_analysis()
    
    async def _direct_analysis(self) -> AnalysisResult:
        """Perform direct analysis without pipeline complexity."""
        from .models.results import AnalysisSummary
        from .detectors.base import DetectionContext
        
        # Create execution context
        execution_context = ExecutionContext(
            analyzer_version="2.0.0",
            input_files=self._log_files,
            input_formats=list(self._log_formats.values())
        )
        
        try:
            # Step 1: Parse log files
            all_network_traces = []
            
            for log_file in self._log_files:
                log_format = self._log_formats.get(log_file)
                
                # Find appropriate parser
                parser = None
                for p in self._parsers:
                    if hasattr(p, 'supported_format') and p.supported_format == log_format:
                        parser = p
                        break
                
                if parser:
                    logger.info(f"Parsing {log_file} with {type(parser).__name__}")
                    parse_result = await parser.parse(log_file)
                    all_network_traces.extend(parse_result.network_traces)
                    logger.info(f"Parsed {len(parse_result.network_traces)} traces from {log_file}")
                else:
                    logger.warning(f"No parser found for {log_file} (format: {log_format})")
            
            logger.info(f"Total network traces: {len(all_network_traces)}")
            
            # Step 2: Run detectors
            all_issues = []
            
            if all_network_traces:
                context = DetectionContext(
                    network_traces=all_network_traces,
                    service_domains=[self._config.target_service] if self._config.target_service else [],
                    confidence_threshold=0.5
                )
                
                for detector in self._detectors:
                    logger.info(f"Running {type(detector).__name__}")
                    detection_result = await detector.detect(context)
                    all_issues.extend(detection_result.issues_found)
                    logger.info(f"Found {len(detection_result.issues_found)} issues with {type(detector).__name__}")
            
            logger.info(f"Total issues found: {len(all_issues)}")
            
            # Step 3: Calculate score (more reasonable for high-risk sessions)
            overall_score = 100
            for issue in all_issues:
                # Handle both enum and string severity values
                if hasattr(issue.severity, 'value'):
                    severity = issue.severity.value.lower()
                else:
                    severity = str(issue.severity).lower()
                
                if severity == 'critical':
                    overall_score -= 3  # Reduced from 20 to 3
                elif severity == 'high':
                    overall_score -= 2  # Reduced from 10 to 2
                elif severity == 'medium':
                    overall_score -= 1  # Reduced from 5 to 1
                elif severity == 'low':
                    overall_score -= 0.5  # Reduced from 2 to 0.5
            
            overall_score = max(0, int(overall_score))
            
            # Step 4: Create result
            summary = AnalysisSummary(
                status=AnalysisStatus.SUCCESS,
                overall_score=overall_score,
                analysis_duration_ms=100  # Placeholder
            )
            
            result = AnalysisResult(
                summary=summary,
                execution_context=execution_context
            )
            
            # Add issues to result
            for issue in all_issues:
                result.add_issue(issue)
            
            # Add network traces to result
            for trace in all_network_traces:
                result.add_network_trace(trace)
            
            result.finalize_result()
            
            return result
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            
            # Create failed result
            summary = AnalysisSummary(
                status=AnalysisStatus.FAILED,
                overall_score=0
            )
            
            result = AnalysisResult(
                summary=summary,
                execution_context=execution_context
            )
            
            result.finalize_result()
            return result
    
    async def stream_analysis(self) -> AsyncIterator[Dict[str, Any]]:
        """
        Perform streaming analysis with real-time results.
        
        Yields:
            Analysis results as they become available
        """
        # Create execution context
        execution_context = ExecutionContext(
            analyzer_version="2.0.0",
            input_files=self._log_files
        )
        
        # Create processing context
        processing_context = ProcessingContext(
            execution_id=execution_context.execution_id,
            target_service=self._config.target_service,
            geography=self._config.geography
        )
        
        try:
            # Initialize pipeline
            await self._pipeline.initialize()
            
            # Stream results from pipeline
            input_stream = self._create_input_stream()
            
            async for result in self._pipeline.execute_streaming(input_stream, processing_context):
                yield result
                
        finally:
            await self._pipeline.shutdown()
    
    async def _create_input_stream(self) -> AsyncIterator[Dict[str, Any]]:
        """Create input stream from log files."""
        for log_file in self._log_files:
            yield {
                'file_path': log_file,
                'format': self._log_formats.get(log_file),
                'timestamp': datetime.now(timezone.utc)
            }


# Export public API
__all__ = [
    'AnalyzerBuilder',
    'NetStealthAnalyzer',
]
