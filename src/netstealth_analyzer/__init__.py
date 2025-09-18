"""
NetStealth Analyzer v2.0 - Advanced Security Analysis Framework

A comprehensive, async-first security analysis framework for detecting proxy leaks,
TLS fingerprinting, browser configuration issues, and network anomalies.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+

Example Usage:
    Basic analysis:
    ```python
    import asyncio
    from netstealth_analyzer import NetStealthAnalyzer
    
    async def main():
        analyzer = (
            NetStealthAnalyzer.create()
                .with_logs("session.har", "mitmproxy.log")
                .for_service("example.com")
                .build()
        )
        
        result = await analyzer.analyze()
        print(f"Analysis score: {result.summary.overall_score}/100")
        print(f"Issues found: {len(result.issues)}")
    
    asyncio.run(main())
    ```
    
    Streaming analysis:
    ```python
    async def streaming_analysis():
        analyzer = (
            NetStealthAnalyzer.create()
                .with_logs("large_session.har")
                .enable_streaming()
                .track_progress(lambda c, t, m: print(f"{c}/{t}: {m}"))
                .build()
        )
        
        async for update in analyzer.stream_analysis():
            print(f"Update: {update['type']}")
    
    asyncio.run(streaming_analysis())
    ```
"""

# Version information
__version__ = "2.0.0"
__author__ = "NetStealth Analyzer Team"
__license__ = "MIT"

# Core imports - Main API
from .analyzer import NetStealthAnalyzer
from .builder import AnalyzerBuilder
from .config import (
    NetStealthConfig, ConfigurationManager,
    get_config, load_config, save_config,
    create_sample_config
)

# Core components
from .core.events import EventBus, AnalysisEvent, get_event_bus
from .core.errors import (
    NetStealthError, ConfigurationError, ValidationError,
    TimeoutError, ParseError, DetectionError
)
from .core.interfaces import (
    IComponent, ILogParser, IDetector, IReporter,
    ProcessingContext, ProcessingResult, ComponentMetadata
)

# Data models
from .models.enums import (
    SeverityLevel, RiskLevel, IssueCategory, LogFormat,
    AnalysisStatus, DetectionConfidence
)
from .models.issues import (
    Issue, IssueEvidence, IssueLocation, DetectionRule,
    RemediationSuggestion
)
from .models.network import (
    NetworkHop, NetworkTrace, TLSInfo, ProxyInfo, GeographicInfo
)
from .models.results import (
    AnalysisResult, AnalysisSummary, PerformanceMetrics,
    ExecutionContext
)

# Compatibility layer
from .compatibility import (
    TaskGroup, override, FeatureDetector,
    get_python_version, has_feature
)

# Convenience functions
def create_analyzer() -> AnalyzerBuilder:
    """
    Create a new analyzer builder for fluent configuration.
    
    Returns:
        New AnalyzerBuilder instance for method chaining
        
    Example:
        ```python
        analyzer = (
            create_analyzer()
                .with_log("session.har")
                .for_service("example.com")
                .build()
        )
        ```
    """
    return NetStealthAnalyzer.create()


async def quick_analyze(
    log_file: str,
    service: str = None,
    geography: str = None
) -> AnalysisResult:
    """
    Perform a quick analysis of a single log file.
    
    Args:
        log_file: Path to the log file to analyze
        service: Optional target service domain
        geography: Optional expected geography (ISO country code)
        
    Returns:
        Analysis results
        
    Example:
        ```python
        result = await quick_analyze("session.har", "example.com", "US")
        print(f"Score: {result.summary.overall_score}/100")
        ```
    """
    builder = create_analyzer().with_log(log_file)
    
    if service:
        builder = builder.for_service(service)
    
    if geography:
        builder = builder.in_geography(geography)
    
    analyzer = builder.build()
    
    try:
        return await analyzer.analyze()
    finally:
        await analyzer.shutdown()


def get_version_info() -> dict:
    """
    Get detailed version information.
    
    Returns:
        Dictionary with version details
    """
    return {
        'version': __version__,
        'author': __author__,
        'license': __license__,
        'python_version': get_python_version(),
        'features': {
            'async_support': True,
            'streaming': True,
            'plugins': True,
            'multiple_formats': True,
            'event_driven': True,
        }
    }


# Export public API
__all__ = [
    # Version info
    '__version__',
    '__author__',
    '__license__',
    
    # Main classes
    'NetStealthAnalyzer',
    'AnalyzerBuilder',
    
    # Configuration
    'NetStealthConfig',
    'ConfigurationManager',
    'get_config',
    'load_config',
    'save_config',
    'create_sample_config',
    
    # Core components
    'EventBus',
    'AnalysisEvent',
    'get_event_bus',
    
    # Errors
    'NetStealthError',
    'ConfigurationError',
    'ValidationError',
    'TimeoutError',
    'ParseError',
    'DetectionError',
    
    # Interfaces
    'IComponent',
    'ILogParser',
    'IDetector',
    'IReporter',
    'ProcessingContext',
    'ProcessingResult',
    'ComponentMetadata',
    
    # Enums
    'SeverityLevel',
    'RiskLevel',
    'IssueCategory',
    'LogFormat',
    'AnalysisStatus',
    'DetectionConfidence',
    
    # Models
    'Issue',
    'IssueEvidence',
    'IssueLocation',
    'DetectionRule',
    'RemediationSuggestion',
    'NetworkHop',
    'NetworkTrace',
    'TLSInfo',
    'ProxyInfo',
    'GeographicInfo',
    'AnalysisResult',
    'AnalysisSummary',
    'PerformanceMetrics',
    'ExecutionContext',
    
    # Compatibility
    'TaskGroup',
    'override',
    'FeatureDetector',
    'get_python_version',
    'has_feature',
    
    # Convenience functions
    'create_analyzer',
    'quick_analyze',
    'get_version_info',
]


# Configure logging for the package
import logging

# Create package logger
_logger = logging.getLogger(__name__)
_logger.setLevel(logging.INFO)

# Add null handler to prevent "No handler found" warnings
_logger.addHandler(logging.NullHandler())

# Optional: Add console handler for development
if not _logger.handlers:
    _console_handler = logging.StreamHandler()
    _console_handler.setLevel(logging.INFO)
    _formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    _console_handler.setFormatter(_formatter)
    _logger.addHandler(_console_handler)


# Package initialization message
_logger.info(f"NetStealth Analyzer v{__version__} initialized")
_logger.debug(f"Python version: {get_python_version()}")
_logger.debug(f"Available features: {list(get_version_info()['features'].keys())}")
