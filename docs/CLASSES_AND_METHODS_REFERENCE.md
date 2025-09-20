# NetStealth Analyzer - Classes and Methods Reference

**Version:** 2.0.0  
**Author:** NetStealth Analyzer Team  
**Python:** 3.11+  
**Generated:** September 18, 2025

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Main API Classes](#main-api-classes)
3. [Core Infrastructure](#core-infrastructure)
4. [Data Models](#data-models)
5. [Component System](#component-system)
6. [Utility Functions](#utility-functions)
7. [Alphabetical Index](#alphabetical-index)

---

## Executive Summary

The NetStealth Analyzer is a comprehensive, async-first security analysis framework designed for detecting proxy leaks, TLS fingerprinting, browser configuration issues, and network anomalies. The framework uses a sophisticated layered architecture with over 200 classes, methods, and functions.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Main API Layer                           │
│  NetStealthAnalyzer + AnalyzerBuilder (Fluent Interface)   │
├─────────────────────────────────────────────────────────────┤
│                 Core Infrastructure                         │
│  Pipeline Engine, Event System, Interfaces, Error Handling │
├─────────────────────────────────────────────────────────────┤
│                   Data Models                               │
│  Enums, Issues, Network Traces, Results, Configurations    │
├─────────────────────────────────────────────────────────────┤
│                 Component System                            │
│  Parsers, Detectors, Reporters, Plugins with Registry      │
├─────────────────────────────────────────────────────────────┤
│                Processing Pipeline                          │
│  Async Orchestration with Dependency Management            │
└─────────────────────────────────────────────────────────────┘
```

---

## Main API Classes

### NetStealthAnalyzer

**Location:** `src/netstealth_analyzer/analyzer.py`  
**Description:** Main analyzer class providing the primary interface for security analysis operations.

#### Constructor
```python
def __init__(
    config: NetStealthConfig,
    event_bus: EventBus,
    log_files: List[Path],
    log_formats: Dict[Path, LogFormat],
    parsers: List[ILogParser],
    detectors: List[IDetector],
    reporters: List[IReporter],
    plugins: List[IComponent],
    progress_callback: Optional[Callable] = None
)
```

#### Class Methods
- `create() -> AnalyzerBuilder` - Create a new analyzer builder for fluent configuration

#### Properties
- `config -> NetStealthConfig` - Get the current configuration
- `is_initialized -> bool` - Check if analyzer is initialized
- `current_analysis -> Optional[AnalysisResult]` - Get current analysis result

#### Core Methods
- `async initialize() -> None` - Initialize the analyzer and all components
- `async shutdown() -> None` - Shutdown the analyzer and cleanup resources
- `async analyze() -> AnalysisResult` - Perform complete analysis of configured log files
- `async stream_analysis() -> AsyncIterator[Dict[str, Any]]` - Perform streaming analysis with real-time results
- `async analyze_single_file(file_path: Union[str, Path], format: Optional[LogFormat] = None) -> AnalysisResult` - Analyze a single log file

#### Analysis Methods
- `get_analysis_summary() -> Optional[Dict[str, Any]]` - Get summary of current analysis
- `get_issues_by_severity(severity: str) -> List[Dict[str, Any]]` - Get issues filtered by severity level
- `get_network_traces() -> List[Dict[str, Any]]` - Get all network traces from current analysis

#### Internal Methods
- `async _create_input_stream() -> AsyncIterator[Dict[str, Any]]` - Create input stream from log files
- `_process_streaming_result(result: Dict[str, Any]) -> Optional[Dict[str, Any]]` - Process streaming result from pipeline
- `_process_pipeline_results(result: AnalysisResult, pipeline_data: Dict[str, Any]) -> None` - Process results from pipeline execution
- `_calculate_overall_score(pipeline_data: Dict[str, Any]) -> int` - Calculate overall analysis score

#### Context Manager Methods
- `async __aenter__()` - Async context manager entry
- `async __aexit__(exc_type, exc_val, exc_tb)` - Async context manager exit

---

### AnalyzerBuilder

**Location:** `src/netstealth_analyzer/builder.py`  
**Description:** Fluent API builder for creating NetStealth Analyzer instances with method chaining.

#### Constructor
```python
def __init__()
```

#### Input Configuration Methods
- `with_log(file_path: Union[str, Path], format: Optional[LogFormat] = None) -> AnalyzerBuilder` - Add a single log file
- `with_logs(*file_paths: Union[str, Path]) -> AnalyzerBuilder` - Add multiple log files
- `with_log_directory(directory: Union[str, Path], pattern: str = "*", recursive: bool = False) -> AnalyzerBuilder` - Add all log files from directory

#### Target Configuration Methods
- `for_service(service_domain: str) -> AnalyzerBuilder` - Set target service domain
- `in_geography(country_code: str) -> AnalyzerBuilder` - Set expected geographic location

#### Feature Configuration Methods
- `enable_streaming() -> AnalyzerBuilder` - Enable streaming analysis
- `enable_fingerprint_analysis() -> AnalyzerBuilder` - Enable detailed fingerprint analysis
- `enable_session_timeline() -> AnalyzerBuilder` - Enable session timeline generation
- `enable_diff_analysis() -> AnalyzerBuilder` - Enable differential analysis

#### Component Configuration Methods
- `with_parser(parser: ILogParser) -> AnalyzerBuilder` - Add custom parser component
- `with_detector(detector: IDetector) -> AnalyzerBuilder` - Add custom detector component
- `with_detectors(*detector_names: str) -> AnalyzerBuilder` - Add multiple detectors by name from registry
- `with_reporter(reporter: IReporter) -> AnalyzerBuilder` - Add custom reporter component
- `with_plugin(plugin: IComponent) -> AnalyzerBuilder` - Add plugin component

#### Event Configuration Methods
- `on(event: AnalysisEvent, handler: Callable) -> AnalyzerBuilder` - Register event handler
- `track_progress(callback: Callable[[int, int, str], None]) -> AnalyzerBuilder` - Set progress tracking callback
- `track_events(handler: Callable[[AnalysisEvent, Any], None]) -> AnalyzerBuilder` - Set general event handler

#### Output Configuration Methods
- `output_to(directory: Union[str, Path]) -> AnalyzerBuilder` - Set output directory
- `output_formats(*formats: str) -> AnalyzerBuilder` - Set output formats
- `include_raw_data(include: bool = True) -> AnalyzerBuilder` - Include raw log data in reports

#### Performance Configuration Methods
- `max_concurrent_parsers(count: int) -> AnalyzerBuilder` - Set maximum concurrent parsers
- `timeout(seconds: float) -> AnalyzerBuilder` - Set analysis timeout
- `memory_limit(mb: int) -> AnalyzerBuilder` - Set memory usage limit

#### Configuration Loading Methods
- `with_config(config: Union[NetStealthConfig, Dict[str, Any], str, Path]) -> AnalyzerBuilder` - Load configuration from various sources
- `with_config_file(file_path: Union[str, Path]) -> AnalyzerBuilder` - Load configuration from file

#### Validation and Building Methods
- `validate() -> AnalyzerBuilder` - Validate current configuration
- `build() -> NetStealthAnalyzer` - Build configured analyzer instance

#### Internal Methods
- `_detect_log_format(file_path: Path) -> Optional[LogFormat]` - Auto-detect log format
- `_apply_settings_to_config() -> None` - Apply builder settings to configuration

---

## Core Infrastructure

### PipelineEngine

**Location:** `src/netstealth_analyzer/core/pipeline.py`  
**Description:** Core pipeline processing engine that orchestrates execution of parsers, detectors, and reporters.

#### Constructor
```python
def __init__(
    name: str = "pipeline",
    event_bus: Optional[EventBus] = None,
    max_concurrent_stages: int = 5,
    default_timeout: float = 300.0
)
```

#### Properties
- `metadata -> ComponentMetadata` - Get component metadata
- `status -> ComponentStatus` - Get current component status
- `pipeline_status -> PipelineStatus` - Get current pipeline execution status
- `current_execution -> Optional[PipelineExecution]` - Get current pipeline execution

#### Lifecycle Methods
- `async initialize(config: Optional[Dict[str, Any]] = None) -> None` - Initialize pipeline engine
- `async shutdown() -> None` - Shutdown pipeline engine
- `validate_configuration(config: Dict[str, Any]) -> bool` - Validate pipeline configuration
- `get_health_status() -> Dict[str, Any]` - Get pipeline health status

#### Stage Management Methods
- `async add_stage(stage: PipelineStage) -> None` - Add stage to pipeline
- `async remove_stage(stage_name: str) -> bool` - Remove stage from pipeline
- `get_stage_order() -> List[str]` - Get execution order of stages
- `validate_pipeline() -> bool` - Validate pipeline configuration

#### Execution Methods
- `async execute(input_data: Any, context: ProcessingContext) -> ProcessingResult[Dict[str, Any]]` - Execute pipeline with input data
- `async execute_streaming(input_stream: AsyncIterator[Any], context: ProcessingContext) -> AsyncIterator[Dict[str, Any]]` - Execute pipeline with streaming input

#### Control Methods
- `async pause_execution() -> None` - Pause pipeline execution
- `async resume_execution() -> None` - Resume paused pipeline execution
- `async cancel_execution() -> None` - Cancel current pipeline execution

#### Statistics Methods
- `get_execution_history(limit: Optional[int] = None) -> List[PipelineExecution]` - Get pipeline execution history
- `get_statistics() -> Dict[str, Any]` - Get comprehensive pipeline statistics
- `clear_history() -> None` - Clear execution history

#### Internal Methods
- `_rebuild_stage_order() -> None` - Rebuild stage execution order
- `_has_circular_dependencies() -> bool` - Check for circular dependencies
- `async _execute_stages(input_data: Any, execution: PipelineExecution) -> Dict[str, Any]` - Execute all pipeline stages
- `async _execute_stage_level(stage_names: List[str], input_results: Dict[str, Any], execution: PipelineExecution) -> Dict[str, Any]` - Execute stages at dependency level
- `async _execute_single_stage(stage_name: str, input_data: Dict[str, Any], execution: PipelineExecution) -> Any` - Execute single pipeline stage
- `async _call_stage_component(component: IComponent, input_data: Dict[str, Any], context: Optional[ProcessingContext]) -> Any` - Call stage component
- `_check_dependencies_met(stage_name: str, execution: PipelineExecution) -> bool` - Check if dependencies are met
- `_get_stage_levels() -> List[List[str]]` - Group stages by dependency level
- `_update_average_execution_time(duration_ms: int) -> None` - Update average execution time

### EventBus

**Location:** `src/netstealth_analyzer/core/events.py`  
**Description:** Event system for progress tracking and component communication.

#### Core Methods
- `async emit(event: AnalysisEvent, data: Any) -> None` - Emit analysis event
- `on(event: AnalysisEvent, handler: Callable) -> None` - Register event handler
- `off(event: AnalysisEvent, handler: Callable) -> None` - Unregister event handler

### Core Interfaces

**Location:** `src/netstealth_analyzer/core/interfaces.py`  
**Description:** Abstract interfaces and contracts for all components.

#### Base Interfaces
- `IComponent` - Base interface for all components
- `ILogParser` - Interface for log file parsers
- `IDetector` - Interface for security issue detectors
- `IReporter` - Interface for report generators
- `IPipeline` - Interface for analysis pipelines
- `IRegistry[T]` - Generic interface for component registries
- `IConfigurable` - Interface for configurable components

#### Specialized Interfaces
- `IStreamingParser` - Extended interface for real-time streaming parsers
- `IBatchDetector` - Extended interface for batch processing detectors
- `IPlugin` - Base interface for all plugins
- `IParserPlugin` - Interface for parser plugins
- `IDetectorPlugin` - Interface for detector plugins

---

## Data Models

### Enumerations

#### SeverityLevel
**Location:** `src/netstealth_analyzer/models/enums.py`

- `CRITICAL = "critical"`
- `HIGH = "high"`
- `MEDIUM = "medium"`
- `LOW = "low"`
- `INFO = "info"`

**Properties:**
- `numeric_value -> int` - Get numeric value for sorting
- `color_code -> str` - Get color code for UI display

#### IssueCategory
**Location:** `src/netstealth_analyzer/models/enums.py`

**Core Categories:**
- `TLS_FINGERPRINT = "tls_fingerprint"`
- `PROXY_DETECTION = "proxy_detection"`
- `BROWSER_CONFIG = "browser_config"`
- `NETWORK_ANOMALY = "network_anomaly"`

**Extended Categories:**
- `AUTHENTICATION = "authentication"`
- `AUTHORIZATION = "authorization"`
- `SESSION_MANAGEMENT = "session_management"`
- `DATA_LEAKAGE = "data_leakage"`
- `PRIVACY_VIOLATION = "privacy_violation"`
- `PERFORMANCE = "performance"`
- `CONFIGURATION = "configuration"`
- `COMPLIANCE = "compliance"`

**Geographic Categories:**
- `GEOGRAPHIC_LEAK = "geographic_leak"`
- `IP_EXPOSURE = "ip_exposure"`
- `DNS_LEAK = "dns_leak"`

**Browser Categories:**
- `JAVASCRIPT_FINGERPRINT = "javascript_fingerprint"`
- `WEBRTC_LEAK = "webrtc_leak"`
- `CANVAS_FINGERPRINT = "canvas_fingerprint"`
- `FONT_FINGERPRINT = "font_fingerprint"`

**Properties:**
- `display_name -> str` - Get human-readable display name
- `description -> str` - Get detailed description

#### DetectionConfidence
**Location:** `src/netstealth_analyzer/models/enums.py`

- `VERY_HIGH = "very_high"` - 90-100%
- `HIGH = "high"` - 75-89%
- `MEDIUM = "medium"` - 50-74%
- `LOW = "low"` - 25-49%
- `VERY_LOW = "very_low"` - 0-24%

**Properties:**
- `numeric_range -> tuple[float, float]` - Get numeric confidence range
- `numeric_value -> float` - Get representative numeric value

**Class Methods:**
- `from_score(score: float) -> DetectionConfidence` - Convert numeric score to confidence level

#### LogFormat
**Location:** `src/netstealth_analyzer/models/enums.py`

**Network Proxy Logs:**
- `MITMPROXY = "mitmproxy"`
- `BURP_SUITE = "burp_suite"`
- `CHARLES_PROXY = "charles_proxy"`

**Browser Logs:**
- `HAR = "har"`
- `BROWSER_CONSOLE = "browser_console"`
- `CHROME_DEBUG = "chrome_debug"`
- `FIREFOX_DEBUG = "firefox_debug"`

**Custom Formats:**
- `POC_EXECUTION = "poc_execution"`
- `NETSTEALTH_NATIVE = "netstealth_native"`

**Generic Formats:**
- `JSON_LINES = "json_lines"`
- `CSV = "csv"`
- `PLAIN_TEXT = "plain_text"`

**Properties:**
- `file_extensions -> List[str]` - Get typical file extensions
- `supports_streaming -> bool` - Check if format supports streaming

#### AnalysisStatus
**Location:** `src/netstealth_analyzer/models/enums.py`

- `SUCCESS = "success"`
- `PARTIAL_SUCCESS = "partial_success"`
- `FAILED = "failed"`
- `CANCELLED = "cancelled"`
- `TIMEOUT = "timeout"`

**Properties:**
- `is_successful -> bool` - Check if status indicates success
- `is_terminal -> bool` - Check if status is terminal

#### NetworkProtocol
**Location:** `src/netstealth_analyzer/models/enums.py`

- `HTTP = "http"`
- `HTTPS = "https"`
- `HTTP2 = "http2"`
- `HTTP3 = "http3"`
- `WEBSOCKET = "websocket"`
- `WEBSOCKET_SECURE = "websocket_secure"`
- `TCP = "tcp"`
- `UDP = "udp"`
- `QUIC = "quic"`

**Properties:**
- `is_encrypted -> bool` - Check if protocol uses encryption
- `default_port -> int` - Get default port for protocol

#### TLSVersion
**Location:** `src/netstealth_analyzer/models/enums.py`

- `SSL_30 = "ssl_3.0"`
- `TLS_10 = "tls_1.0"`
- `TLS_11 = "tls_1.1"`
- `TLS_12 = "tls_1.2"`
- `TLS_13 = "tls_1.3"`

**Properties:**
- `is_secure -> bool` - Check if TLS version is secure
- `numeric_version -> float` - Get numeric version for comparison

#### ProxyType
**Location:** `src/netstealth_analyzer/models/enums.py`

- `HTTP = "http"`
- `HTTPS = "https"`
- `SOCKS4 = "socks4"`
- `SOCKS5 = "socks5"`
- `TRANSPARENT = "transparent"`
- `REVERSE = "reverse"`
- `FORWARD = "forward"`

**Properties:**
- `supports_authentication -> bool` - Check if proxy supports authentication
- `supports_udp -> bool` - Check if proxy supports UDP traffic

### Data Classes

#### ProcessingContext
**Location:** `src/netstealth_analyzer/core/interfaces.py`

**Fields:**
- `session_id: UUID`
- `correlation_id: Optional[UUID]`
- `configuration: Dict[str, Any]`
- `metadata: Dict[str, Any]`
- `file_path: Optional[Path]`
- `start_time: datetime`
- `timeout_seconds: Optional[float]`

**Methods:**
- `with_correlation(correlation_id: UUID) -> ProcessingContext` - Create copy with correlation ID

#### ProcessingResult[T]
**Location:** `src/netstealth_analyzer/core/interfaces.py`

**Fields:**
- `success: bool`
- `data: Optional[T]`
- `error: Optional[Exception]`
- `warnings: List[str]`
- `metadata: Dict[str, Any]`
- `processing_time_ms: Optional[int]`
- `items_processed: int`

**Properties:**
- `has_warnings -> bool` - Check if result has warnings

**Methods:**
- `add_warning(message: str) -> None` - Add warning message

#### ComponentMetadata
**Location:** `src/netstealth_analyzer/core/interfaces.py`

**Fields:**
- `name: str`
- `version: str`
- `description: str`
- `author: str`
- `priority: Priority`
- `tags: List[str]`
- `dependencies: List[str]`
- `supported_formats: List[str]`
- `configuration_schema: Optional[Dict[str, Any]]`
- `created_at: datetime`

---

## Component System

### Detector Base Classes

#### IDetector
**Location:** `src/netstealth_analyzer/detectors/base.py`

**Properties:**
- `name -> str` - Get detector name
- `version -> str` - Get detector version
- `description -> str` - Get detector description
- `categories -> List[IssueCategory]` - Get issue categories
- `detection_rules -> List[DetectionRule]` - Get detection rules

**Core Methods:**
- `async detect(context: DetectionContext) -> DetectionResult` - Perform detection
- `async stream_detect(context: DetectionContext) -> AsyncIterator[Issue]` - Stream detection results
- `async validate_context(context: DetectionContext) -> bool` - Validate detection context

**Helper Methods:**
- `async _emit_progress(event_type: str, data: Any = None) -> None` - Emit progress event
- `_create_issue(...) -> Issue` - Create issue with standard formatting
- `_create_evidence(...) -> IssueEvidence` - Create evidence with standard formatting

#### BaseDetector
**Location:** `src/netstealth_analyzer/detectors/base.py`

**Constructor:**
```python
def __init__(
    event_bus: Optional[EventBus] = None,
    confidence_threshold: float = 0.7
)
```

**Properties:**
- `confidence_threshold: float` - Minimum confidence threshold
- `ip_detection_services: List[str]` - Common IP detection services
- `proxy_headers: List[str]` - Common proxy-revealing headers

**Core Methods:**
- `async stream_detect(context: DetectionContext) -> AsyncIterator[Issue]` - Default streaming implementation

**Helper Methods:**
- `_is_service_domain(domain: str, service_domains: List[str]) -> bool` - Check if domain is service-related
- `_is_ip_detection_service(domain: str) -> bool` - Check if domain is IP detection service
- `_has_proxy_headers(headers: List[Dict[str, str]]) -> bool` - Check for proxy headers
- `_extract_domain(url: str) -> str` - Extract domain from URL
- `_is_suspicious_timing(timing_ms: float) -> bool` - Check if timing is suspicious
- `_calculate_confidence(evidence_count: int, total_traces: int, base_confidence: float = 0.5) -> DetectionConfidence` - Calculate detection confidence
- `_init_statistics() -> Dict[str, Any]` - Initialize statistics dictionary
- `_finalize_statistics(stats: Dict[str, Any], issues: List[Issue], start_time: float) -> None` - Finalize statistics

#### DetectionContext
**Location:** `src/netstealth_analyzer/detectors/base.py`

**Fields:**
- `network_traces: List[NetworkTrace]`
- `service_domains: List[str]`
- `target_geography: Optional[Dict[str, Any]]`
- `strict_mode: bool`
- `confidence_threshold: float`
- `session_id: Optional[str]`
- `analysis_timestamp: Optional[datetime]`
- `metadata: Dict[str, Any]`

#### DetectionResult
**Location:** `src/netstealth_analyzer/detectors/base.py`

**Fields:**
- `detector_name: str`
- `detector_version: str`
- `execution_time_ms: float`
- `issues_found: List[Issue]`
- `detection_rules_applied: List[DetectionRule]`
- `statistics: Dict[str, Any]`
- `errors: List[Dict[str, Any]]`

**Properties:**
- `is_successful -> bool` - Check if detection completed successfully
- `issue_count -> int` - Get total number of issues
- `high_severity_count -> int` - Get count of high severity issues

**Methods:**
- `get_issues_by_category(category: IssueCategory) -> List[Issue]` - Get issues by category
- `get_issues_by_severity(min_severity: SeverityLevel) -> List[Issue]` - Get issues by severity

---

## Utility Functions

### Package Level Functions

**Location:** `src/netstealth_analyzer/__init__.py`

#### Factory Functions
- `create_analyzer() -> AnalyzerBuilder` - Create new analyzer builder
- `async quick_analyze(log_file: str, service: str = None, geography: str = None) -> AnalysisResult` - Perform quick analysis

#### Configuration Functions
- `get_config() -> NetStealthConfig` - Get current configuration
- `load_config(file_path: Union[str, Path]) -> NetStealthConfig` - Load configuration from file
- `save_config(config: NetStealthConfig, file_path: Union[str, Path]) -> None` - Save configuration to file
- `create_sample_config() -> NetStealthConfig` - Create sample configuration

#### Event Functions
- `get_event_bus() -> EventBus` - Get global event bus

#### Utility Functions
- `get_version_info() -> dict` - Get detailed version information

### Compatibility Functions

**Location:** `src/netstealth_analyzer/compatibility.py`

#### Version Detection
- `get_python_version() -> str` - Get Python version string
- `has_feature(feature: str) -> bool` - Check if feature is available

#### Async Utilities
- `TaskGroup` - Async task group for Python 3.11+ compatibility
- `override` - Method override decorator

---

## Alphabetical Index

### A
- `add_evidence()` - Issue.add_evidence()
- `add_remediation()` - Issue.add_remediation()
- `add_stage()` - PipelineEngine.add_stage()
- `add_warning()` - ProcessingResult.add_warning()
- `analyze()` - NetStealthAnalyzer.analyze()
- `analyze_single_file()` - NetStealthAnalyzer.analyze_single_file()
- `AnalysisEvent` - Core event enumeration
- `AnalysisResult` - Analysis result data model
- `AnalysisStatus` - Analysis status enumeration
- `AnalyzerBuilder` - Fluent API builder class

### B
- `BaseDetector` - Base detector implementation
- `build()` - AnalyzerBuilder.build()

### C
- `cancel_execution()` - PipelineEngine.cancel_execution()
- `clear_history()` - PipelineEngine.clear_history()
- `ComponentMetadata` - Component metadata data class
- `ComponentStatus` - Component status enumeration
- `config` - NetStealthAnalyzer.config property
- `create()` - NetStealthAnalyzer.create()
- `create_analyzer()` - Package factory function
- `current_analysis` - NetStealthAnalyzer.current_analysis property
- `current_execution` - PipelineEngine.current_execution property

### D
- `detect()` - IDetector.detect()
- `DetectionConfidence` - Confidence level enumeration
- `DetectionContext` - Detection context data class
- `DetectionResult` - Detection result data class
- `DetectionRule` - Detection rule data model

### E
- `emit()` - EventBus.emit()
- `enable_diff_analysis()` - AnalyzerBuilder.enable_diff_analysis()
- `enable_fingerprint_analysis()` - AnalyzerBuilder.enable_fingerprint_analysis()
- `enable_session_timeline()` - AnalyzerBuilder.enable_session_timeline()
- `enable_streaming()` - AnalyzerBuilder.enable_streaming()
- `EventBus` - Event system class
- `execute()` - PipelineEngine.execute()
- `execute_streaming()` - PipelineEngine.execute_streaming()

### F
- `for_service()` - AnalyzerBuilder.for_service()
- `from_score()` - DetectionConfidence.from_score()

### G
- `get_analysis_summary()` - NetStealthAnalyzer.get_analysis_summary()
- `get_configuration()` - IConfigurable.get_configuration()
- `get_event_bus()` - Package utility function
- `get_execution_history()` - PipelineEngine.get_execution_history()
- `get_health_status()` - IComponent.get_health_status()
- `get_issues_by_category()` - DetectionResult.get_issues_by_category()
- `get_issues_by_severity()` - Various classes
- `get_network_traces()` - NetStealthAnalyzer.get_network_traces()
- `get_python_version()` - Compatibility function
- `get_stage_order()` - PipelineEngine.get_stage_order()
- `get_statistics()` - PipelineEngine.get_statistics()
- `get_version_info()` - Package utility function

### H
- `has_feature()` - Compatibility function
- `has_warnings` - ProcessingResult.has_warnings property

### I
- `IComponent` - Base component interface
- `IDetector` - Detector interface
- `in_geography()` - AnalyzerBuilder.in_geography()
- `include_raw_data()` - AnalyzerBuilder.include_raw_data()
- `initialize()` - Various classes
- `ILogParser` - Parser interface
- `IPipeline` - Pipeline interface
- `IReporter` - Reporter interface
- `is_initialized` - NetStealthAnalyzer.is_initialized property
- `is_successful` - Various result classes
- `Issue` - Issue data model
- `IssueCategory` - Issue category enumeration
- `IssueEvidence` - Issue evidence data model

### L
- `load_config()` - Package utility function
- `LogFormat` - Log format enumeration

### M
- `max_concurrent_parsers()` - AnalyzerBuilder.max_concurrent_parsers()
- `memory_limit()` - AnalyzerBuilder.memory_limit()
- `metadata` - Various classes

### N
- `NetStealthAnalyzer` - Main analyzer class
- `NetStealthConfig` - Configuration class
- `NetworkProtocol` - Network protocol enumeration
- `NetworkTrace` - Network trace data model
- `numeric_value` - Various enumeration properties

### O
- `on()` - EventBus.on() and AnalyzerBuilder.on()
- `output_formats()` - AnalyzerBuilder.output_formats()
- `output_to()` - AnalyzerBuilder.output_to()

### P
- `parse()` - ILogParser.parse()
- `pause_execution()` - PipelineEngine.pause_execution()
- `PipelineEngine` - Core pipeline class
- `PipelineExecution` - Pipeline execution state
- `PipelineStatus` - Pipeline status enumeration
- `ProcessingContext` - Processing context data class
- `ProcessingResult` - Processing result data class
- `ProxyType` - Proxy type enumeration

### Q
- `quick_analyze()` - Package utility function

### R
- `remove_stage()` - PipelineEngine.remove_stage()
- `resume_execution()` - PipelineEngine.resume_execution()

### S
- `save_config()` - Package utility function
- `SeverityLevel` - Severity level enumeration
- `shutdown()` - Various classes
- `StageExecution` - Stage execution state
- `status` - Various classes
- `stream_analysis()` - NetStealthAnalyzer.stream_analysis()
- `stream_detect()` - IDetector.stream_detect()

### T
- `timeout()` - AnalyzerBuilder.timeout()
- `TLSVersion` - TLS version enumeration
- `to_dict()` - Various data models
- `track_events()` - AnalyzerBuilder.track_events()
- `track_progress()` - AnalyzerBuilder.track_progress()

### V
- `validate()` - AnalyzerBuilder.validate()
- `validate_configuration()` - Various classes
- `validate_context()` - IDetector.validate_context()
- `validate_pipeline()` - PipelineEngine.validate_pipeline()

### W
- `with_config()` - AnalyzerBuilder.with_config()
- `with_detector()` - AnalyzerBuilder.with_detector()
- `with_log()` - AnalyzerBuilder.with_log()
- `with_logs()` - AnalyzerBuilder.with_logs()
- `with_parser()` - AnalyzerBuilder.with_parser()
- `with_plugin()` - AnalyzerBuilder.with_plugin()
- `with_reporter()` - AnalyzerBuilder.with_reporter()

---

## Usage Examples

### Basic Analysis
```python
import asyncio
from netstealth_analyzer import create_analyzer

async def main():
    analyzer = (
