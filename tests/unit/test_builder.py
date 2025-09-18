"""
Comprehensive tests for NetStealth Analyzer Builder module.

This test module provides extensive coverage for the AnalyzerBuilder class,
including fluent API methods, configuration validation, and builder patterns.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import pytest
import tempfile
import json
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from pathlib import Path
from typing import Dict, Any, List

from netstealth_analyzer.builder import AnalyzerBuilder, NetStealthAnalyzer
from netstealth_analyzer.config import NetStealthConfig
from netstealth_analyzer.core.events import EventBus, AnalysisEvent
from netstealth_analyzer.core.interfaces import ILogParser, IDetector, IReporter, IComponent
from netstealth_analyzer.core.errors import ConfigurationError, ValidationError
from netstealth_analyzer.models.enums import LogFormat, AnalysisStatus


@pytest.fixture
def temp_log_file():
    """Create a temporary log file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False) as f:
        f.write('{"log": {"entries": []}}')
        temp_path = Path(f.name)
    
    yield temp_path
    
    # Cleanup
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_log_files():
    """Create multiple temporary log files for testing."""
    files = []
    
    # Create HAR file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False) as f:
        f.write('{"log": {"entries": []}}')
        files.append(Path(f.name))
    
    # Create mitmproxy file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.mitm', delete=False) as f:
        f.write('test mitmproxy data')
        files.append(Path(f.name))
    
    # Create JSON file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('{"test": "data"}')
        files.append(Path(f.name))
    
    yield files
    
    # Cleanup
    for file_path in files:
        if file_path.exists():
            file_path.unlink()


@pytest.fixture
def temp_directory():
    """Create a temporary directory with log files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create some test files
        (temp_path / "test1.har").write_text('{"log": {"entries": []}}')
        (temp_path / "test2.mitm").write_text('test data')
        (temp_path / "test3.json").write_text('{"test": "data"}')
        (temp_path / "readme.txt").write_text('not a log file')
        
        # Create subdirectory
        sub_dir = temp_path / "subdir"
        sub_dir.mkdir()
        (sub_dir / "nested.har").write_text('{"log": {"entries": []}}')
        
        yield temp_path


@pytest.fixture
def mock_components():
    """Create mock components for testing."""
    # Mock parser
    parser = Mock(spec=ILogParser)
    parser.parse = AsyncMock()
    
    # Mock detector
    detector = Mock(spec=IDetector)
    detector.detect = AsyncMock()
    
    # Mock reporter
    reporter = Mock(spec=IReporter)
    reporter.generate_report = AsyncMock()
    
    # Mock plugin
    plugin = Mock(spec=IComponent)
    plugin.metadata = Mock()
    plugin.metadata.name = "test_plugin"
    
    return {
        'parser': parser,
        'detector': detector,
        'reporter': reporter,
        'plugin': plugin
    }


@pytest.fixture
def sample_config():
    """Create a sample configuration for testing."""
    return {
        'target_service': 'example.com',
        'geography': 'US',
        'performance': {
            'max_concurrent_parsers': 4,
            'timeout_seconds': 300
        }
    }


class TestAnalyzerBuilderInit:
    """Test AnalyzerBuilder initialization."""

    def test_init_default_values(self):
        """Test builder initialization with default values."""
        builder = AnalyzerBuilder()
        
        assert isinstance(builder._config, NetStealthConfig)
        assert builder._event_bus is None
        assert builder._log_files == []
        assert builder._log_formats == {}
        assert builder._target_service is None
        assert builder._geography is None
        assert builder._custom_rules == []
        assert builder._parsers == []
        assert builder._detectors == []
        assert builder._reporters == []
        assert builder._plugins == []
        assert builder._event_handlers == {}
        assert builder._progress_callback is None
        assert not builder._enable_streaming
        assert not builder._enable_fingerprint_analysis
        assert not builder._enable_session_timeline
        assert not builder._enable_diff_analysis
        assert builder._output_formats == ["json"]
        assert builder._output_directory is None
        assert not builder._include_raw_data
        assert builder._max_concurrent_parsers is None
        assert builder._timeout_seconds is None
        assert builder._memory_limit_mb is None


class TestAnalyzerBuilderInputConfiguration:
    """Test input configuration methods."""

    def test_with_log_success(self, temp_log_file):
        """Test adding a single log file successfully."""
        builder = AnalyzerBuilder()
        result = builder.with_log(temp_log_file, LogFormat.HAR)
        
        assert result is builder  # Method chaining
        assert temp_log_file in builder._log_files
        assert builder._log_formats[temp_log_file] == LogFormat.HAR

    def test_with_log_auto_detect_format(self, temp_log_file):
        """Test auto-detection of log format."""
        builder = AnalyzerBuilder()
        builder.with_log(temp_log_file)
        
        assert temp_log_file in builder._log_files
        assert builder._log_formats[temp_log_file] == LogFormat.HAR

    def test_with_log_file_not_found(self):
        """Test error when log file doesn't exist."""
        builder = AnalyzerBuilder()
        
        with pytest.raises(ConfigurationError, match="Log file not found"):
            builder.with_log("/nonexistent/file.har")

    def test_with_logs_multiple_files(self, temp_log_files):
        """Test adding multiple log files."""
        builder = AnalyzerBuilder()
        result = builder.with_logs(*temp_log_files)
        
        assert result is builder
        assert len(builder._log_files) == len(temp_log_files)
        for file_path in temp_log_files:
            assert file_path in builder._log_files

    def test_with_log_directory_non_recursive(self, temp_directory):
        """Test adding log files from directory (non-recursive)."""
        builder = AnalyzerBuilder()
        result = builder.with_log_directory(temp_directory, "*.har")
        
        assert result is builder
        # Should find test1.har but not nested.har
        har_files = [f for f in builder._log_files if f.suffix == '.har']
        assert len(har_files) == 1
        assert har_files[0].name == "test1.har"

    def test_with_log_directory_recursive(self, temp_directory):
        """Test adding log files from directory (recursive)."""
        builder = AnalyzerBuilder()
        result = builder.with_log_directory(temp_directory, "*.har", recursive=True)
        
        assert result is builder
        # Should find both test1.har and nested.har
        har_files = [f for f in builder._log_files if f.suffix == '.har']
        assert len(har_files) == 2

    def test_with_log_directory_all_files(self, temp_directory):
        """Test adding all files from directory."""
        builder = AnalyzerBuilder()
        result = builder.with_log_directory(temp_directory)
        
        assert result is builder
        # Should find all files except subdirectory
        assert len(builder._log_files) == 4  # test1.har, test2.mitm, test3.json, readme.txt

    def test_with_log_directory_not_found(self):
        """Test error when directory doesn't exist."""
        builder = AnalyzerBuilder()
        
        with pytest.raises(ConfigurationError, match="Directory not found"):
            builder.with_log_directory("/nonexistent/directory")

    def test_detect_log_format_various_extensions(self):
        """Test log format detection for various file extensions."""
        builder = AnalyzerBuilder()
        
        test_cases = [
            ('.har', LogFormat.HAR),
            ('.mitm', LogFormat.MITMPROXY),
            ('.flow', LogFormat.MITMPROXY),
            ('.json', LogFormat.JSON_LINES),
            ('.jsonl', LogFormat.JSON_LINES),
            ('.ndjson', LogFormat.JSON_LINES),
            ('.csv', LogFormat.CSV),
            ('.log', LogFormat.PLAIN_TEXT),
            ('.txt', LogFormat.PLAIN_TEXT),
            ('.unknown', None)
        ]
        
        for extension, expected_format in test_cases:
            path = Path(f"test{extension}")
            result = builder._detect_log_format(path)
            assert result == expected_format


class TestAnalyzerBuilderTargetConfiguration:
    """Test target configuration methods."""

    def test_for_service_success(self):
        """Test setting target service successfully."""
        builder = AnalyzerBuilder()
        result = builder.for_service("example.com")
        
        assert result is builder
        assert builder._target_service == "example.com"
        assert builder._config.target_service == "example.com"

    def test_for_service_empty_string(self):
        """Test error with empty service domain."""
        builder = AnalyzerBuilder()
        
        with pytest.raises(ConfigurationError, match="Service domain must be a non-empty string"):
            builder.for_service("")

    def test_for_service_none(self):
        """Test error with None service domain."""
        builder = AnalyzerBuilder()
        
        with pytest.raises(ConfigurationError, match="Service domain must be a non-empty string"):
            builder.for_service(None)

    def test_in_geography_success(self):
        """Test setting geography successfully."""
        builder = AnalyzerBuilder()
        result = builder.in_geography("us")
        
        assert result is builder
        assert builder._geography == "US"
        assert builder._config.geography == "US"

    def test_in_geography_invalid_length(self):
        """Test error with invalid country code length."""
        builder = AnalyzerBuilder()
        
        with pytest.raises(ConfigurationError, match="Country code must be a 2-letter ISO code"):
            builder.in_geography("USA")

    def test_in_geography_empty(self):
        """Test error with empty country code."""
        builder = AnalyzerBuilder()
        
        with pytest.raises(ConfigurationError, match="Country code must be a 2-letter ISO code"):
            builder.in_geography("")


class TestAnalyzerBuilderFeatureConfiguration:
    """Test feature configuration methods."""

    def test_enable_streaming(self):
        """Test enabling streaming analysis."""
        builder = AnalyzerBuilder()
        result = builder.enable_streaming()
        
        assert result is builder
        assert builder._enable_streaming is True

    def test_enable_fingerprint_analysis(self):
        """Test enabling fingerprint analysis."""
        builder = AnalyzerBuilder()
        result = builder.enable_fingerprint_analysis()
        
        assert result is builder
        assert builder._enable_fingerprint_analysis is True

    def test_enable_session_timeline(self):
        """Test enabling session timeline."""
        builder = AnalyzerBuilder()
        result = builder.enable_session_timeline()
        
        assert result is builder
        assert builder._enable_session_timeline is True

    def test_enable_diff_analysis(self):
        """Test enabling diff analysis."""
        builder = AnalyzerBuilder()
        result = builder.enable_diff_analysis()
        
        assert result is builder
        assert builder._enable_diff_analysis is True


class TestAnalyzerBuilderComponentConfiguration:
    """Test component configuration methods."""

    def test_with_parser_success(self, mock_components):
        """Test adding a parser component."""
        builder = AnalyzerBuilder()
        result = builder.with_parser(mock_components['parser'])
        
        assert result is builder
        assert mock_components['parser'] in builder._parsers

    def test_with_parser_invalid_interface(self):
        """Test error with invalid parser interface."""
        builder = AnalyzerBuilder()
        invalid_parser = Mock()
        del invalid_parser.parse  # Remove required method
        
        with pytest.raises(ConfigurationError, match="Parser must implement ILogParser interface"):
            builder.with_parser(invalid_parser)

    def test_with_detector_success(self, mock_components):
        """Test adding a detector component."""
        builder = AnalyzerBuilder()
        result = builder.with_detector(mock_components['detector'])
        
        assert result is builder
        assert mock_components['detector'] in builder._detectors

    def test_with_detector_invalid_interface(self):
        """Test error with invalid detector interface."""
        builder = AnalyzerBuilder()
        invalid_detector = Mock()
        del invalid_detector.detect  # Remove required method
        
        with pytest.raises(ConfigurationError, match="Detector must implement IDetector interface"):
            builder.with_detector(invalid_detector)

    def test_with_reporter_success(self, mock_components):
        """Test adding a reporter component."""
        builder = AnalyzerBuilder()
        result = builder.with_reporter(mock_components['reporter'])
        
        assert result is builder
        assert mock_components['reporter'] in builder._reporters

    def test_with_reporter_invalid_interface(self):
        """Test error with invalid reporter interface."""
        builder = AnalyzerBuilder()
        invalid_reporter = Mock()
        del invalid_reporter.generate_report  # Remove required method
        
        with pytest.raises(ConfigurationError, match="Reporter must implement IReporter interface"):
            builder.with_reporter(invalid_reporter)

    def test_with_plugin_success(self, mock_components):
        """Test adding a plugin component."""
        builder = AnalyzerBuilder()
        result = builder.with_plugin(mock_components['plugin'])
        
        assert result is builder
        assert mock_components['plugin'] in builder._plugins

    def test_with_plugin_invalid_interface(self):
        """Test error with invalid plugin interface."""
        builder = AnalyzerBuilder()
        invalid_plugin = Mock()
        del invalid_plugin.metadata  # Remove required attribute
        
        with pytest.raises(ConfigurationError, match="Plugin must implement IComponent interface"):
            builder.with_plugin(invalid_plugin)


class TestAnalyzerBuilderEventConfiguration:
    """Test event configuration methods."""

    def test_on_event_handler(self):
        """Test registering event handler."""
        builder = AnalyzerBuilder()
        handler = Mock()
        result = builder.on(AnalysisEvent.ANALYSIS_STARTED, handler)
        
        assert result is builder
        assert AnalysisEvent.ANALYSIS_STARTED in builder._event_handlers
        assert handler in builder._event_handlers[AnalysisEvent.ANALYSIS_STARTED]

    def test_on_multiple_handlers_same_event(self):
        """Test registering multiple handlers for same event."""
        builder = AnalyzerBuilder()
        handler1 = Mock()
        handler2 = Mock()
        
        builder.on(AnalysisEvent.ANALYSIS_STARTED, handler1)
        builder.on(AnalysisEvent.ANALYSIS_STARTED, handler2)
        
        handlers = builder._event_handlers[AnalysisEvent.ANALYSIS_STARTED]
        assert len(handlers) == 2
        assert handler1 in handlers
        assert handler2 in handlers

    def test_track_progress(self):
        """Test setting progress callback."""
        builder = AnalyzerBuilder()
        callback = Mock()
        result = builder.track_progress(callback)
        
        assert result is builder
        assert builder._progress_callback == callback

    def test_track_events(self):
        """Test setting general event handler."""
        builder = AnalyzerBuilder()
        handler = Mock()
        result = builder.track_events(handler)
        
        assert result is builder
        # Should register handler for all events
        assert len(builder._event_handlers) == len(AnalysisEvent)


class TestAnalyzerBuilderOutputConfiguration:
    """Test output configuration methods."""

    def test_output_to_success(self):
        """Test setting output directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            builder = AnalyzerBuilder()
            result = builder.output_to(temp_dir)
            
            assert result is builder
            assert builder._output_directory == Path(temp_dir)
            assert builder._output_directory.exists()

    def test_output_to_creates_directory(self):
        """Test that output_to creates directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            new_dir = Path(temp_dir) / "new_output_dir"
            
            builder = AnalyzerBuilder()
            builder.output_to(new_dir)
            
            assert new_dir.exists()
            assert builder._output_directory == new_dir

    def test_output_formats_success(self):
        """Test setting output formats."""
        builder = AnalyzerBuilder()
        result = builder.output_formats("json", "markdown", "html")
        
        assert result is builder
        assert builder._output_formats == ["json", "markdown", "html"]

    def test_output_formats_invalid_format(self):
        """Test error with invalid output format."""
        builder = AnalyzerBuilder()
        
        with pytest.raises(ConfigurationError, match="Unsupported format: invalid"):
            builder.output_formats("json", "invalid")

    def test_include_raw_data_true(self):
        """Test including raw data."""
        builder = AnalyzerBuilder()
        result = builder.include_raw_data(True)
        
        assert result is builder
        assert builder._include_raw_data is True

    def test_include_raw_data_false(self):
        """Test not including raw data."""
        builder = AnalyzerBuilder()
        result = builder.include_raw_data(False)
        
        assert result is builder
        assert builder._include_raw_data is False

    def test_include_raw_data_default(self):
        """Test default behavior of include_raw_data."""
        builder = AnalyzerBuilder()
        result = builder.include_raw_data()
        
        assert result is builder
        assert builder._include_raw_data is True


class TestAnalyzerBuilderPerformanceConfiguration:
    """Test performance configuration methods."""

    def test_max_concurrent_parsers_success(self):
        """Test setting max concurrent parsers."""
        builder = AnalyzerBuilder()
        result = builder.max_concurrent_parsers(8)
        
        assert result is builder
        assert builder._max_concurrent_parsers == 8

    def test_max_concurrent_parsers_invalid(self):
        """Test error with invalid concurrent parsers count."""
        builder = AnalyzerBuilder()
        
        with pytest.raises(ConfigurationError, match="Concurrent parsers count must be >= 1"):
            builder.max_concurrent_parsers(0)

    def test_timeout_success(self):
        """Test setting timeout."""
        builder = AnalyzerBuilder()
        result = builder.timeout(300.5)
        
        assert result is builder
        assert builder._timeout_seconds == 300.5

    def test_timeout_invalid(self):
        """Test error with invalid timeout."""
        builder = AnalyzerBuilder()
        
        with pytest.raises(ConfigurationError, match="Timeout must be positive"):
            builder.timeout(-10)

    def test_memory_limit_success(self):
        """Test setting memory limit."""
        builder = AnalyzerBuilder()
        result = builder.memory_limit(1024)
        
        assert result is builder
        assert builder._memory_limit_mb == 1024

    def test_memory_limit_invalid(self):
        """Test error with invalid memory limit."""
        builder = AnalyzerBuilder()
        
        with pytest.raises(ConfigurationError, match="Memory limit must be >= 64MB"):
            builder.memory_limit(32)


class TestAnalyzerBuilderConfigurationLoading:
    """Test configuration loading methods."""

    def test_with_config_object(self):
        """Test loading configuration from NetStealthConfig object."""
        config = NetStealthConfig()
        config.target_service = "test.com"
        
        builder = AnalyzerBuilder()
        result = builder.with_config(config)
        
        assert result is builder
        assert builder._config == config
        assert builder._config.target_service == "test.com"

    def test_with_config_dict(self, sample_config):
        """Test loading configuration from dictionary."""
        builder = AnalyzerBuilder()
        result = builder.with_config(sample_config)
        
        assert result is builder
        assert builder._config.target_service == "example.com"
        assert builder._config.geography == "US"

    def test_with_config_file_path(self, sample_config):
        """Test loading configuration from file path."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sample_config, f)
            config_file = Path(f.name)
        
        try:
            with patch('netstealth_analyzer.builder.get_config_manager') as mock_get_manager:
                mock_manager = Mock()
                mock_config = NetStealthConfig(**sample_config)
                mock_manager.load_from_file.return_value = mock_config
                mock_get_manager.return_value = mock_manager
                
                builder = AnalyzerBuilder()
                result = builder.with_config(config_file)
                
                assert result is builder
                mock_manager.load_from_file.assert_called_once_with(config_file)
        finally:
            config_file.unlink()

    def test_with_config_invalid_type(self):
        """Test error with invalid configuration type."""
        builder = AnalyzerBuilder()
        
        with pytest.raises(ConfigurationError, match="Unsupported config type"):
            builder.with_config(123)

    def test_with_config_file_convenience_method(self):
        """Test with_config_file convenience method."""
        with patch.object(AnalyzerBuilder, 'with_config') as mock_with_config:
            builder = AnalyzerBuilder()
            config_path = Path("test_config.json")
            
            result = builder.with_config_file(config_path)
            
            mock_with_config.assert_called_once_with(config_path)
            assert result == mock_with_config.return_value


class TestAnalyzerBuilderValidation:
    """Test configuration validation."""

    def test_validate_success(self, temp_log_file):
        """Test successful validation."""
        builder = AnalyzerBuilder()
        builder.with_log(temp_log_file)
        
        result = builder.validate()
        assert result is builder

    def test_validate_no_log_files(self):
        """Test validation error with no log files."""
        builder = AnalyzerBuilder()
        
        with pytest.raises(ConfigurationError, match="No log files specified"):
            builder.validate()

    def test_validate_missing_log_file(self):
        """Test validation error with missing log file."""
        builder = AnalyzerBuilder()
        builder._log_files.append(Path("/nonexistent/file.log"))
        
        with pytest.raises(ConfigurationError, match="Log file not found"):
            builder.validate()

    def test_validate_geography_without_service(self, temp_log_file):
        """Test validation error with geography but no target service."""
        builder = AnalyzerBuilder()
        builder.with_log(temp_log_file)
        builder.in_geography("US")
        
        with pytest.raises(ConfigurationError, match="Target service required when geography is specified"):
            builder.validate()

    def test_validate_invalid_output_directory(self, temp_log_file):
        """Test validation error with invalid output directory."""
        builder = AnalyzerBuilder()
        builder.with_log(temp_log_file)
        builder._output_directory = Path("/nonexistent/parent/output")
        
        with pytest.raises(ConfigurationError, match="Output directory parent does not exist"):
            builder.validate()

    def test_validate_excessive_concurrent_parsers(self, temp_log_file):
        """Test validation warning with too many concurrent parsers."""
        builder = AnalyzerBuilder()
        builder.with_log(temp_log_file)
        builder.max_concurrent_parsers(100)
        
        with pytest.raises(ConfigurationError, match="Maximum concurrent parsers should not exceed 50"):
            builder.validate()

    def test_validate_excessive_timeout(self, temp_log_file):
        """Test validation warning with excessive timeout."""
        builder = AnalyzerBuilder()
        builder.with_log(temp_log_file)
        builder.timeout(7200)  # 2 hours
        
        with pytest.raises(ConfigurationError, match="Timeout should not exceed 1 hour"):
            builder.validate()

    def test_validate_excessive_memory_limit(self, temp_log_file):
        """Test validation warning with excessive memory limit."""
        builder = AnalyzerBuilder()
        builder.with_log(temp_log_file)
        builder.memory_limit(10240)  # 10GB
        
        with pytest.raises(ConfigurationError, match="Memory limit should not exceed 8GB"):
            builder.validate()


class TestAnalyzerBuilderBuild:
    """Test analyzer building."""

    def test_build_success(self, temp_log_file, mock_components):
        """Test successful analyzer building."""
        with patch('netstealth_analyzer.builder.get_event_bus') as mock_get_bus:
            mock_event_bus = Mock(spec=EventBus)
            mock_event_bus.on = Mock()
            mock_get_bus.return_value = mock_event_bus
            
            # Import and patch the actual analyzer class
            with patch('netstealth_analyzer.analyzer.NetStealthAnalyzer') as mock_analyzer_class:
                mock_analyzer = Mock()
                mock_analyzer_class.return_value = mock_analyzer
                
                builder = AnalyzerBuilder()
                builder.with_log(temp_log_file)
                builder.for_service("example.com")
                builder.with_parser(mock_components['parser'])
                
                result = builder.build()
                
                assert result == mock_analyzer
                mock_analyzer_class.assert_called_once()

    def test_build_with_event_handlers(self, temp_log_file):
        """Test building with event handlers."""
        with patch('netstealth_analyzer.builder.get_event_bus') as mock_get_bus:
            mock_event_bus = Mock(spec=EventBus)
            mock_event_bus.on = Mock()
            mock_get_bus.return_value = mock_event_bus
            
            with patch('netstealth_analyzer.builder.NetStealthAnalyzer'):
                handler = Mock()
                
                builder = AnalyzerBuilder()
                builder.with_log(temp_log_file)
                builder.on(AnalysisEvent.ANALYSIS_STARTED, handler)
                
                builder.build()
                
                # Verify event handler was registered
                mock_event_bus.on.assert_called_once_with(AnalysisEvent.ANALYSIS_STARTED, handler)

    def test_build_validation_failure(self):
        """Test build failure due to validation error."""
        builder = AnalyzerBuilder()
        # No log files - should fail validation
        
        with pytest.raises(ConfigurationError, match="No log files specified"):
            builder.build()

    def test_apply_settings_to_config(self, temp_log_file):
        """Test that builder settings are applied to config."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('netstealth_analyzer.builder.get_event_bus'):
                with patch('netstealth_analyzer.builder.NetStealthAnalyzer'):
                    builder = AnalyzerBuilder()
                    builder.with_log(temp_log_file)
                    builder.max_concurrent_parsers(8)
                    builder.timeout(600)
                    builder.memory_limit(2048)
                    builder.output_to(temp_dir)
                    builder.include_raw_data(True)
                    builder.enable_fingerprint_analysis()
                    builder.enable_session_timeline()
                    builder.enable_diff_analysis()
                    builder.enable_streaming()
                    
                    builder.build()
                    
                    # Check that settings were applied to config
                    config = builder._config
                    assert config.performance.max_concurrent_parsers == 8
                    assert config.performance.timeout_seconds == 600
                    assert config.performance.max_memory_usage_mb == 2048
                    assert config.output.directory == Path(temp_dir)
                    assert config.output.include_raw_data is True
                    assert config.custom.get('fingerprint_analysis') is True
                    assert config.custom.get('session_timeline') is True
                    assert config.custom.get('diff_analysis') is True
                    assert config.custom.get('streaming') is True


class TestAnalyzerBuilderIntegration:
    """Integration tests for AnalyzerBuilder."""

    def test_fluent_api_chaining(self, temp_log_files, mock_components):
        """Test fluent API method chaining."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('netstealth_analyzer.builder.get_event_bus'):
                with patch('netstealth_analyzer.analyzer.NetStealthAnalyzer') as mock_analyzer_class:
                    mock_analyzer = Mock()
                    mock_analyzer_class.return_value = mock_analyzer
                    
                    # Test complete fluent chain
                    result = (AnalyzerBuilder()
                             .with_logs(*temp_log_files)
                             .for_service("example.com")
                             .in_geography("US")
                             .with_parser(mock_components['parser'])
                             .with_detector(mock_components['detector'])
                             .with_reporter(mock_components['reporter'])
                             .with_plugin(mock_components['plugin'])
                             .enable_streaming()
                             .enable_fingerprint_analysis()
                             .track_progress(Mock())
                             .output_to(temp_dir)
                             .output_formats("json", "markdown")
                             .max_concurrent_parsers(4)
                             .timeout(300)
                             .memory_limit(1024)
                             .build())
                    
                    assert result == mock_analyzer

    def test_complex_configuration_scenario(self, temp_directory, mock_components):
        """Test complex configuration scenario."""
        with tempfile.TemporaryDirectory() as output_dir:
            with patch('netstealth_analyzer.builder.get_event_bus'):
                with patch('netstealth_analyzer.builder.NetStealthAnalyzer'):
                    progress_callback = Mock()
                    event_handler = Mock()
                    
                    builder = AnalyzerBuilder()
                    
                    # Complex configuration
                    builder.with_log_directory(temp_directory, "*.har", recursive=True)
                    builder.for_service("complex-service.com")
                    builder.in_geography("DE")
                    builder.with_parser(mock_components['parser'])
                    builder.with_detector(mock_components['detector'])
                    builder.with_reporter(mock_components['reporter'])
                    builder.with_plugin(mock_components['plugin'])
                    builder.on(AnalysisEvent.ANALYSIS_STARTED, event_handler)
                    builder.on(AnalysisEvent.ANALYSIS_COMPLETED, event_handler)
                    builder.track_progress(progress_callback)
                    builder.enable_streaming()
                    builder.enable_fingerprint_analysis()
                    builder.enable_session_timeline()
                    builder.enable_diff_analysis()
                    builder.output_to(output_dir)
                    builder.output_formats("json", "markdown", "html")
                    builder.include_raw_data(True)
                    builder.max_concurrent_parsers(6)
                    builder.timeout(900)
                    builder.memory_limit(4096)
                    
                    # Validate and build
                    result = builder.validate().build()
                    
                    # Verify complex configuration was applied
                    assert len(builder._log_files) >= 2  # Should find HAR files
                    assert builder._target_service == "complex-service.com"
                    assert builder._geography == "DE"
                    assert len(builder._parsers) == 1
                    assert len(builder._detectors) == 1
                    assert len(builder._reporters) == 1
                    assert len(builder._plugins) == 1
                    assert builder._enable_streaming
                    assert builder._enable_fingerprint_analysis
                    assert builder._enable_session_timeline
                    assert builder._enable_diff_analysis
                    assert builder._progress_callback == progress_callback
                    assert builder._output_formats == ["json", "markdown", "html"]
                    assert builder._include_raw_data
                    assert builder._max_concurrent_parsers == 6
                    assert builder._timeout_seconds == 900
                    assert builder._memory_limit_mb == 4096


class TestAnalyzerBuilderEdgeCases:
    """Test edge cases and error conditions."""

    def test_multiple_calls_same_method(self, temp_log_files):
        """Test calling the same configuration method multiple times."""
        builder = AnalyzerBuilder()
        
        # Multiple service calls - should use last one
        builder.for_service("first.com")
        builder.for_service("second.com")
        assert builder._target_service == "second.com"
        
        # Multiple geography calls - should use last one
        builder.in_geography("US")
        builder.in_geography("UK")
        assert builder._geography == "UK"
        
        # Multiple log files - should accumulate
        builder.with_log(temp_log_files[0])
        builder.with_log(temp_log_files[1])
        assert len(builder._log_files) == 2

    def test_empty_directory_handling(self):
        """Test handling of empty directories."""
        with tempfile.TemporaryDirectory() as empty_dir:
            builder = AnalyzerBuilder()
            result = builder.with_log_directory(empty_dir)
            
            assert result is builder
            assert len(builder._log_files) == 0

    def test_mixed_file_types_in_directory(self, temp_directory):
        """Test handling mixed file types in directory."""
        builder = AnalyzerBuilder()
        builder.with_log_directory(temp_directory, "*")
        
        # Should include all files
        assert len(builder._log_files) == 4
        
        # Check format detection worked
        har_files = [f for f in builder._log_files if f.suffix == '.har']
        mitm_files = [f for f in builder._log_files if f.suffix == '.mitm']
        json_files = [f for f in builder._log_files if f.suffix == '.json']
        txt_files = [f for f in builder._log_files if f.suffix == '.txt']
        
        assert len(har_files) == 1
        assert len(mitm_files) == 1
        assert len(json_files) == 1
        assert len(txt_files) == 1

    def test_validation_with_partial_configuration(self, temp_log_file):
        """Test validation with minimal valid configuration."""
        builder = AnalyzerBuilder()
        builder.with_log(temp_log_file)
        
        # Should pass with just a log file
        result = builder.validate()
        assert result is builder

    def test_configuration_reset_behavior(self, temp_log_file):
        """Test that configuration doesn't reset unexpectedly."""
        builder = AnalyzerBuilder()
        
        # Set up configuration
        builder.with_log(temp_log_file)
        builder.for_service("test.com")
        builder.enable_streaming()
        
        # Verify configuration persists
        assert temp_log_file in builder._log_files
        assert builder._target_service == "test.com"
        assert builder._enable_streaming
        
        # Add more configuration
        builder.in_geography("US")
        builder.enable_fingerprint_analysis()
        
        # Verify all configuration still present
        assert temp_log_file in builder._log_files
        assert builder._target_service == "test.com"
        assert builder._geography == "US"
        assert builder._enable_streaming
        assert builder._enable_fingerprint_analysis


class TestAnalyzerBuilderStaticMethods:
    """Test static and class methods."""

    def test_netstealth_analyzer_create_method(self):
        """Test NetStealthAnalyzer.create() returns AnalyzerBuilder."""
        result = NetStealthAnalyzer.create()
        assert isinstance(result, AnalyzerBuilder)

    def test_analyzer_builder_returns_correct_type(self):
        """Test that AnalyzerBuilder methods return correct types."""
        builder = AnalyzerBuilder()
        
        # All fluent methods should return AnalyzerBuilder
        assert isinstance(builder.enable_streaming(), AnalyzerBuilder)
        assert isinstance(builder.enable_fingerprint_analysis(), AnalyzerBuilder)
        assert isinstance(builder.enable_session_timeline(), AnalyzerBuilder)
        assert isinstance(builder.enable_diff_analysis(), AnalyzerBuilder)
