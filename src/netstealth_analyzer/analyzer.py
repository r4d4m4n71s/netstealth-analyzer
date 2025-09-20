"""
Main NetStealth Analyzer module.

This module provides the primary analyzer class that coordinates all components
and provides the main entry point for security analysis operations.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Union, Callable, AsyncIterator
from pathlib import Path
from datetime import datetime, timezone

from .config import NetStealthConfig
from .core.events import EventBus, AnalysisEvent
from .core.interfaces import IComponent, ILogParser, IDetector, IReporter, ProcessingContext
from .core.pipeline import PipelineEngine
from .models.enums import LogFormat, AnalysisStatus
from .models.results import AnalysisResult, ExecutionContext, AnalysisSummary
from .compatibility import override

logger = logging.getLogger(__name__)


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
        """
        Initialize the NetStealth Analyzer.
        
        Args:
            config: Configuration object
            event_bus: Event bus for progress tracking
            log_files: List of log files to analyze
            log_formats: Mapping of files to their formats
            parsers: List of parser components
            detectors: List of detector components
            reporters: List of reporter components
            plugins: List of plugin components
            progress_callback: Optional progress callback function
        """
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
        self._pipeline = PipelineEngine(
            name="netstealth_analyzer",
            event_bus=event_bus
        )
        
        # Track analysis state
        self._is_initialized = False
        self._current_analysis: Optional[AnalysisResult] = None
    
    async def _setup_pipeline_stages(self) -> None:
        """Set up pipeline stages from parsers and detectors."""
        from .core.interfaces import PipelineStage
        
        # Add parser stages (run first)
        parser_stages = []
        for i, parser in enumerate(self._parsers):
            stage_name = f"parser_{type(parser).__name__.lower()}_{i}"
            stage = PipelineStage(
                name=stage_name,
                component=parser,
                depends_on=[],  # Parsers have no dependencies
                parallel=True,  # Parsers can run in parallel
                optional=False,
                timeout_seconds=300.0,
                retry_count=1
            )
            await self._pipeline.add_stage(stage)
            parser_stages.append(stage_name)
        
        # Add detector stages (run after parsers)
        for i, detector in enumerate(self._detectors):
            stage_name = f"detector_{type(detector).__name__.lower()}_{i}"
            stage = PipelineStage(
                name=stage_name,
                component=detector,
                depends_on=parser_stages,  # Detectors depend on all parsers
                parallel=True,  # Detectors can run in parallel
                optional=False,
                timeout_seconds=300.0,
                retry_count=1
            )
            await self._pipeline.add_stage(stage)
        
        # Add reporter stages (run after detectors) if any
        detector_stages = [f"detector_{type(d).__name__.lower()}_{i}" for i, d in enumerate(self._detectors)]
        for i, reporter in enumerate(self._reporters):
            stage_name = f"reporter_{type(reporter).__name__.lower()}_{i}"
            stage = PipelineStage(
                name=stage_name,
                component=reporter,
                depends_on=detector_stages,  # Reporters depend on all detectors
                parallel=False,  # Reporters should run sequentially
                optional=True,   # Reporters are optional
                timeout_seconds=120.0,
                retry_count=0
            )
            await self._pipeline.add_stage(stage)
    
    @classmethod
    def create(cls):
        """
        Create a new analyzer builder for fluent configuration.
        
        Returns:
            New AnalyzerBuilder instance
        """
        from .builder import AnalyzerBuilder
        return AnalyzerBuilder()
    
    @property
    def config(self) -> NetStealthConfig:
        """Get the current configuration."""
        return self._config
    
    @property
    def is_initialized(self) -> bool:
        """Check if analyzer is initialized."""
        return self._is_initialized
    
    @property
    def current_analysis(self) -> Optional[AnalysisResult]:
        """Get the current analysis result if available."""
        return self._current_analysis
    
    async def initialize(self) -> None:
        """Initialize the analyzer and all components."""
        if self._is_initialized:
            return
        
        logger.info("Initializing NetStealth Analyzer...")
        
        try:
            # Initialize pipeline
            await self._pipeline.initialize(self._config.performance.model_dump())
            
            # Set up pipeline stages
            await self._setup_pipeline_stages()
            
            # Initialize all components
            for component_list in [self._parsers, self._detectors, self._reporters, self._plugins]:
                for component in component_list:
                    if hasattr(component, 'initialize'):
                        await component.initialize()
            
            self._is_initialized = True
            logger.info("NetStealth Analyzer initialized successfully")
            
            # Emit initialization event
            await self._event_bus.emit(
                AnalysisEvent.ANALYSIS_STARTED,
                {
                    'analyzer_version': '2.0.0',
                    'log_files_count': len(self._log_files),
                    'components_count': len(self._parsers) + len(self._detectors) + len(self._reporters) + len(self._plugins)
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to initialize analyzer: {e}")
            raise
    
    async def shutdown(self) -> None:
        """Shutdown the analyzer and cleanup resources."""
        if not self._is_initialized:
            return
        
        logger.info("Shutting down NetStealth Analyzer...")
        
        try:
            # Shutdown pipeline
            await self._pipeline.shutdown()
            
            # Shutdown all components
            for component_list in [self._parsers, self._detectors, self._reporters, self._plugins]:
                for component in component_list:
                    if hasattr(component, 'shutdown'):
                        await component.shutdown()
            
            self._is_initialized = False
            logger.info("NetStealth Analyzer shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            raise
    
    async def analyze(self) -> AnalysisResult:
        """
        Perform complete analysis of configured log files.
        
        Returns:
            Complete analysis results
            
        Raises:
            ValueError: If no log files are configured
        """
        if not self._log_files:
            raise ValueError("No log files configured for analysis")
        
        # Use direct processing instead of complex pipeline
        return await self._direct_analysis()
    
    async def _direct_analysis(self) -> AnalysisResult:
        """Perform direct analysis without pipeline complexity."""
        from .detectors.base import DetectionContext
        
        # Create execution context
        execution_context = ExecutionContext(
            analyzer_version="2.0.0",
            input_files=self._log_files,
            input_formats=list(self._log_formats.values())
        )
        
        try:
            logger.info(f"Starting direct analysis with {len(self._log_files)} log files")
            logger.info(f"Available parsers: {[type(p).__name__ for p in self._parsers]}")
            logger.info(f"Log formats: {self._log_formats}")
            
            # Step 1: Parse log files
            all_network_traces = []
            
            for log_file in self._log_files:
                log_format = self._log_formats.get(log_file)
                logger.info(f"Processing {log_file} with format {log_format}")
                
                # Find appropriate parser
                parser = None
                for p in self._parsers:
                    logger.info(f"Checking parser {type(p).__name__}")
                    if hasattr(p, 'supported_format'):
                        logger.info(f"Parser supports format: {p.supported_format}")
                        logger.info(f"Match check: {p.supported_format == log_format}")
                        if p.supported_format == log_format:
                            parser = p
                            break
                    else:
                        logger.warning(f"Parser {type(p).__name__} has no supported_format attribute")
                
                if parser:
                    logger.info(f"Found parser: {type(parser).__name__}")
                    logger.info(f"Parsing {log_file} with {type(parser).__name__}")
                    parse_result = await parser.parse(log_file)
                    logger.info(f"Parse result: {len(parse_result.network_traces)} traces")
                    all_network_traces.extend(parse_result.network_traces)
                    logger.info(f"Parsed {len(parse_result.network_traces)} traces from {log_file}")
                else:
                    logger.error(f"No parser found for {log_file} (format: {log_format})")
            
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
            
            # Step 3: Calculate score
            overall_score = 100
            for issue in all_issues:
                if hasattr(issue.severity, 'value'):
                    severity = issue.severity.value
                else:
                    severity = str(issue.severity).lower()
                
                if severity == 'critical':
                    overall_score -= 20
                elif severity == 'high':
                    overall_score -= 10
                elif severity == 'medium':
                    overall_score -= 5
                elif severity == 'low':
                    overall_score -= 2
            
            overall_score = max(0, overall_score)
            
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
            
            # Store current analysis
            self._current_analysis = result
            
            logger.info(f"Analysis completed successfully. Score: {overall_score}/100")
            
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
            self._current_analysis = result
            return result
    
    async def stream_analysis(self) -> AsyncIterator[Dict[str, Any]]:
        """
        Perform streaming analysis with real-time results.
        
        Yields:
            Analysis results as they become available
            
        Raises:
            RuntimeError: If analyzer is not initialized
        """
        if not self._is_initialized:
            await self.initialize()
        
        if not self._log_files:
            raise ValueError("No log files configured for analysis")
        
        logger.info(f"Starting streaming analysis of {len(self._log_files)} log files")
        
        # Create execution context
        execution_context = ExecutionContext(
            analyzer_version="2.0.0",
            input_files=self._log_files,
            input_formats=list(self._log_formats.values())
        )
        
        # Create processing context
        processing_context = ProcessingContext()
        
        try:
            # Create input stream
            input_stream = self._create_input_stream()
            
            # Stream results from pipeline
            async for result in self._pipeline.execute_streaming(input_stream, processing_context):
                # Process and yield result
                processed_result = self._process_streaming_result(result)
                if processed_result:
                    yield processed_result
                    
                    # Call progress callback if provided
                    if self._progress_callback:
                        try:
                            self._progress_callback(
                                processed_result.get('current', 0),
                                processed_result.get('total', 0),
                                processed_result.get('message', 'Processing...')
                            )
                        except Exception as e:
                            logger.warning(f"Progress callback error: {e}")
                
        except Exception as e:
            logger.error(f"Streaming analysis failed: {e}")
            
            # Yield error result
            yield {
                'type': 'error',
                'error_type': type(e).__name__,
                'error_message': str(e),
                'execution_id': execution_context.execution_id,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    async def analyze_single_file(self, file_path: Union[str, Path], format: Optional[LogFormat] = None) -> AnalysisResult:
        """
        Analyze a single log file.
        
        Args:
            file_path: Path to the log file
            format: Log format (auto-detected if not specified)
            
        Returns:
            Analysis results for the single file
        """
        # Create temporary analyzer configuration
        from .builder import AnalyzerBuilder
        
        builder = AnalyzerBuilder()
        builder.with_log(file_path, format)
        
        # Copy current configuration
        if self._config.target_service:
            builder.for_service(self._config.target_service)
        
        if self._config.geography:
            builder.in_geography(self._config.geography)
        
        # Build and analyze
        temp_analyzer = builder.build()
        
        try:
            return await temp_analyzer.analyze()
        finally:
            await temp_analyzer.shutdown()
    
    def get_analysis_summary(self) -> Optional[Dict[str, Any]]:
        """
        Get summary of the current analysis.
        
        Returns:
            Analysis summary dictionary or None if no analysis has been performed
        """
        if not self._current_analysis:
            return None
        
        return self._current_analysis.get_comprehensive_summary()
    
    def get_issues_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """
        Get issues filtered by severity level.
        
        Args:
            severity: Severity level to filter by
            
        Returns:
            List of issues with the specified severity
        """
        if not self._current_analysis:
            return []
        
        from .models.enums import SeverityLevel
        
        try:
            severity_enum = SeverityLevel(severity.lower())
            issues = self._current_analysis.get_issues_by_severity(severity_enum)
            return [issue.to_dict() for issue in issues]
        except ValueError:
            logger.warning(f"Invalid severity level: {severity}")
            return []
    
    def get_network_traces(self) -> List[Dict[str, Any]]:
        """
        Get all network traces from the current analysis.
        
        Returns:
            List of network trace summaries
        """
        if not self._current_analysis:
            return []
        
        return [trace.get_trace_summary() for trace in self._current_analysis.network_traces]
    
    async def _create_input_stream(self) -> AsyncIterator[Dict[str, Any]]:
        """Create input stream from log files."""
        for i, log_file in enumerate(self._log_files):
            yield {
                'file_path': log_file,
                'format': self._log_formats.get(log_file),
                'file_index': i,
                'total_files': len(self._log_files),
                'timestamp': datetime.now(timezone.utc)
            }
    
    def _process_streaming_result(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a streaming result from the pipeline."""
        if not result:
            return None
        
        # Add metadata
        processed = {
            'type': 'analysis_update',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'analyzer_version': '2.0.0',
            **result
        }
        
        return processed
    
    def _process_pipeline_results(self, result: AnalysisResult, pipeline_data: Dict[str, Any]) -> None:
        """Process results from the pipeline execution."""
        # Extract issues from detector results
        for key, value in pipeline_data.items():
            if key.startswith('detector_') and hasattr(value, 'issues_found'):
                # Process DetectionResult objects
                for issue in value.issues_found:
                    try:
                        result.add_issue(issue)
                    except Exception as e:
                        logger.warning(f"Failed to process issue from {key}: {e}")
            
            elif key.startswith('parser_') and hasattr(value, 'network_traces'):
                # Process ParseResult objects
                for trace in value.network_traces:
                    try:
                        result.add_network_trace(trace)
                    except Exception as e:
                        logger.warning(f"Failed to process network trace from {key}: {e}")
        
        # Extract performance metrics if present
        if 'performance' in pipeline_data:
            try:
                result.performance_metrics = result.performance_metrics.model_copy(
                    update=pipeline_data['performance']
                )
            except Exception as e:
                logger.warning(f"Failed to process performance metrics: {e}")
        
        # Extract processing stats if present
        if 'processing_stats' in pipeline_data:
            try:
                result.processing_stats = result.processing_stats.model_copy(
                    update=pipeline_data['processing_stats']
                )
            except Exception as e:
                logger.warning(f"Failed to process processing stats: {e}")
    
    def _calculate_overall_score(self, pipeline_data: Dict[str, Any]) -> int:
        """Calculate overall analysis score based on pipeline results."""
        base_score = 100
        
        # Deduct points for issues
        issues = pipeline_data.get('issues', [])
        for issue in issues:
            severity = issue.get('severity', 'info')
            if severity == 'critical':
                base_score -= 20
            elif severity == 'high':
                base_score -= 10
            elif severity == 'medium':
                base_score -= 5
            elif severity == 'low':
                base_score -= 2
            else:  # info
                base_score -= 1
        
        # Add points for successful functional indicators
        functional_indicators = pipeline_data.get('functional_indicators', {})
        successful_indicators = sum(1 for indicator in functional_indicators.values() if indicator)
        base_score += successful_indicators * 5
        
        # Ensure score is within bounds
        return max(0, min(100, base_score))
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.shutdown()


# Export public API
__all__ = [
    'NetStealthAnalyzer',
]
