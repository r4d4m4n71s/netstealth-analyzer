"""
Unit tests for NetStealth Analyzer configuration system.

Tests all configuration models, validation logic, file I/O operations,
and the configuration manager functionality.
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import Mock, patch, mock_open
from typing import Dict, Any

from src.netstealth_analyzer.config import (
    # Enums
    LogLevel,
    OutputMode,
    AnalysisMode,
    
    # Configuration models
    LoggingConfig,
    PerformanceConfig,
    SecurityConfig,
    OutputConfig,
    FilterConfig,
    ParserConfig,
    DetectorConfig,
    PluginConfig,
    ReportingConfig,
    NetStealthConfig,
    
    # Manager
    ConfigurationManager,
    
    # Global functions
    get_config_manager,
    get_config,
    load_config,
    save_config,
    
    # Utilities
    create_sample_config,
    validate_config_file,
)
from src.netstealth_analyzer.core.errors import ConfigurationError
from src.netstealth_analyzer.core.interfaces import ReportFormat


class TestConfigEnums:
    """Test configuration enums."""
    
    def test_log_level_enum(self):
        """Test LogLevel enum values."""
        assert LogLevel.DEBUG == "DEBUG"
        assert LogLevel.INFO == "INFO"
        assert LogLevel.WARNING == "WARNING"
        assert LogLevel.ERROR == "ERROR"
        assert LogLevel.CRITICAL == "CRITICAL"
        
        # Test all values are strings
        for level in LogLevel:
            assert isinstance(level.value, str)
    
    def test_output_mode_enum(self):
        """Test OutputMode enum values."""
        assert OutputMode.CONSOLE == "console"
        assert OutputMode.FILE == "file"
        assert OutputMode.BOTH == "both"
        assert OutputMode.STREAM == "stream"
        
        # Test all values are strings
        for mode in OutputMode:
            assert isinstance(mode.value, str)
    
    def test_analysis_mode_enum(self):
        """Test AnalysisMode enum values."""
        assert AnalysisMode.BATCH == "batch"
        assert AnalysisMode.STREAMING == "streaming"
        assert AnalysisMode.INCREMENTAL == "incremental"
        assert AnalysisMode.PARALLEL == "parallel"
        
        # Test all values are strings
        for mode in AnalysisMode:
            assert isinstance(mode.value, str)


class TestLoggingConfig:
    """Test LoggingConfig model."""
    
    def test_logging_config_defaults(self):
        """Test LoggingConfig with default values."""
        config = LoggingConfig()
        
        assert config.level == LogLevel.INFO
        assert config.format == "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        assert config.file_path is None
        assert config.max_file_size_mb == 10
        assert config.backup_count == 5
        assert config.enable_console is True
        assert config.enable_file is False
    
    def test_logging_config_custom_values(self):
        """Test LoggingConfig with custom values."""
        config = LoggingConfig(
            level=LogLevel.DEBUG,
            format="%(levelname)s: %(message)s",
            file_path=Path("/tmp/test.log"),
            max_file_size_mb=50,
            backup_count=10,
            enable_console=False,
            enable_file=True
        )
        
        assert config.level == LogLevel.DEBUG
        assert config.format == "%(levelname)s: %(message)s"
        assert config.file_path == Path("/tmp/test.log")
        assert config.max_file_size_mb == 50
        assert config.backup_count == 10
        assert config.enable_console is False
        assert config.enable_file is True
    
    def test_logging_config_validation(self):
        """Test LoggingConfig field validation."""
        # Valid ranges
        config = LoggingConfig(max_file_size_mb=1, backup_count=1)
        assert config.max_file_size_mb == 1
        assert config.backup_count == 1
        
        config = LoggingConfig(max_file_size_mb=1000, backup_count=50)
        assert config.max_file_size_mb == 1000
        assert config.backup_count == 50
        
        # Invalid ranges should raise validation errors
        with pytest.raises(ValueError):
            LoggingConfig(max_file_size_mb=0)
        
        with pytest.raises(ValueError):
            LoggingConfig(max_file_size_mb=1001)
        
        with pytest.raises(ValueError):
            LoggingConfig(backup_count=0)
        
        with pytest.raises(ValueError):
            LoggingConfig(backup_count=51)


class TestPerformanceConfig:
    """Test PerformanceConfig model."""
    
    def test_performance_config_defaults(self):
        """Test PerformanceConfig with default values."""
        config = PerformanceConfig()
        
        assert config.max_concurrent_parsers == 5
        assert config.max_concurrent_detectors == 10
        assert config.max_memory_usage_mb == 1024
        assert config.timeout_seconds == 300.0
        assert config.enable_parallel_processing is True
        assert config.batch_size == 100
    
    def test_performance_config_custom_values(self):
        """Test PerformanceConfig with custom values."""
        config = PerformanceConfig(
            max_concurrent_parsers=20,
            max_concurrent_detectors=50,
            max_memory_usage_mb=2048,
            timeout_seconds=600.0,
            enable_parallel_processing=False,
            batch_size=500
        )
        
        assert config.max_concurrent_parsers == 20
        assert config.max_concurrent_detectors == 50
        assert config.max_memory_usage_mb == 2048
        assert config.timeout_seconds == 600.0
        assert config.enable_parallel_processing is False
        assert config.batch_size == 500
    
    def test_performance_config_validation(self):
        """Test PerformanceConfig field validation."""
        # Valid ranges
        config = PerformanceConfig(
            max_concurrent_parsers=1,
            max_concurrent_detectors=1,
            max_memory_usage_mb=128,
            timeout_seconds=1.0,
            batch_size=1
        )
        assert config.max_concurrent_parsers == 1
        assert config.max_concurrent_detectors == 1
        assert config.max_memory_usage_mb == 128
        assert config.timeout_seconds == 1.0
        assert config.batch_size == 1
        
        # Test timeout validation - Pydantic raises ValidationError, not ValueError
        from pydantic import ValidationError
        
        with pytest.raises(ValidationError):
            PerformanceConfig(timeout_seconds=0.0)
        
        with pytest.raises(ValidationError):
            PerformanceConfig(timeout_seconds=-1.0)


class TestSecurityConfig:
    """Test SecurityConfig model."""
    
    def test_security_config_defaults(self):
        """Test SecurityConfig with default values."""
        config = SecurityConfig()
        
        assert config.enable_plugin_sandboxing is True
        assert config.allowed_plugin_paths == []
        assert config.max_plugin_execution_time == 60.0
        assert config.enable_network_access is False
        assert config.trusted_domains == []
    
    def test_security_config_custom_values(self):
        """Test SecurityConfig with custom values."""
        paths = [Path("/opt/plugins"), Path("/usr/local/plugins")]
        domains = ["example.com", "trusted.org"]
        
        config = SecurityConfig(
            enable_plugin_sandboxing=False,
            allowed_plugin_paths=paths,
            max_plugin_execution_time=120.0,
            enable_network_access=True,
            trusted_domains=domains
        )
        
        assert config.enable_plugin_sandboxing is False
        assert config.allowed_plugin_paths == paths
        assert config.max_plugin_execution_time == 120.0
        assert config.enable_network_access is True
        assert config.trusted_domains == domains
    
    def test_security_config_path_validation(self):
        """Test SecurityConfig path validation."""
        # Test string paths get converted to Path objects
        config = SecurityConfig(allowed_plugin_paths=["/tmp/plugins", "/opt/plugins"])
        
        assert len(config.allowed_plugin_paths) == 2
        assert all(isinstance(p, Path) for p in config.allowed_plugin_paths)
        assert config.allowed_plugin_paths[0] == Path("/tmp/plugins")
        assert config.allowed_plugin_paths[1] == Path("/opt/plugins")


class TestOutputConfig:
    """Test OutputConfig model."""
    
    def test_output_config_defaults(self):
        """Test OutputConfig with default values."""
        config = OutputConfig()
        
        assert config.mode == OutputMode.CONSOLE
        assert config.directory == Path("./output")
        assert config.filename_template == "netstealth_analysis_{timestamp}"
        assert config.default_format == ReportFormat.JSON
        assert config.include_raw_data is False
        assert config.include_statistics is True
        assert config.compress_output is False
    
    def test_output_config_custom_values(self):
        """Test OutputConfig with custom values."""
        config = OutputConfig(
            mode=OutputMode.FILE,
            directory=Path("/tmp/reports"),
            filename_template="analysis_{date}",
            default_format=ReportFormat.MARKDOWN,
            include_raw_data=True,
            include_statistics=False,
            compress_output=True
        )
        
        assert config.mode == OutputMode.FILE
        assert config.directory == Path("/tmp/reports")
        assert config.filename_template == "analysis_{date}"
        assert config.default_format == ReportFormat.MARKDOWN.value
        assert config.include_raw_data is True
        assert config.include_statistics is False
        assert config.compress_output is True
    
    @patch('pathlib.Path.mkdir')
    def test_output_config_directory_creation(self, mock_mkdir):
        """Test OutputConfig creates directory if it doesn't exist."""
        config = OutputConfig(directory="/tmp/new_reports")
        
        # Directory should be created
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
        assert config.directory == Path("/tmp/new_reports")


class TestFilterConfig:
    """Test FilterConfig model."""
    
    def test_filter_config_defaults(self):
        """Test FilterConfig with default values."""
        config = FilterConfig()
        
        assert config.min_confidence == 0.5
        assert config.severity_levels == ["medium", "high", "critical"]
        assert config.categories == []
        assert config.exclude_categories == []
        assert config.max_issues_per_category is None
    
    def test_filter_config_custom_values(self):
        """Test FilterConfig with custom values."""
        config = FilterConfig(
            min_confidence=0.8,
            severity_levels=["high", "critical"],
            categories=["tls", "proxy"],
            exclude_categories=["browser"],
            max_issues_per_category=10
        )
        
        assert config.min_confidence == 0.8
        assert config.severity_levels == ["high", "critical"]
        assert config.categories == ["tls", "proxy"]
        assert config.exclude_categories == ["browser"]
        assert config.max_issues_per_category == 10
    
    def test_filter_config_confidence_validation(self):
        """Test FilterConfig confidence validation."""
        # Valid confidence values
        config = FilterConfig(min_confidence=0.0)
        assert config.min_confidence == 0.0
        
        config = FilterConfig(min_confidence=1.0)
        assert config.min_confidence == 1.0
        
        # Invalid confidence values - Pydantic raises ValidationError
        from pydantic import ValidationError
        
        with pytest.raises(ValidationError):
            FilterConfig(min_confidence=-0.1)
        
        with pytest.raises(ValidationError):
            FilterConfig(min_confidence=1.1)


class TestParserConfig:
    """Test ParserConfig model."""
    
    def test_parser_config_defaults(self):
        """Test ParserConfig with default values."""
        config = ParserConfig()
        
        assert config.enabled_parsers == ["har", "mitmproxy", "browser"]
        assert config.max_file_size_mb == 100
        assert config.encoding == "utf-8"
        assert config.skip_invalid_entries is True
        assert config.max_parse_errors == 10
        assert config.enable_streaming is True
        assert config.har_config == {}
        assert config.mitmproxy_config == {}
        assert config.browser_config == {}
    
    def test_parser_config_custom_values(self):
        """Test ParserConfig with custom values."""
        har_config = {"include_content": True}
        mitmproxy_config = {"flow_detail": 2}
        browser_config = {"include_console": False}
        
        config = ParserConfig(
            enabled_parsers=["har"],
            max_file_size_mb=200,
            encoding="utf-16",
            skip_invalid_entries=False,
            max_parse_errors=5,
            enable_streaming=False,
            har_config=har_config,
            mitmproxy_config=mitmproxy_config,
            browser_config=browser_config
        )
        
        assert config.enabled_parsers == ["har"]
        assert config.max_file_size_mb == 200
        assert config.encoding == "utf-16"
        assert config.skip_invalid_entries is False
        assert config.max_parse_errors == 5
        assert config.enable_streaming is False
        assert config.har_config == har_config
        assert config.mitmproxy_config == mitmproxy_config
        assert config.browser_config == browser_config


class TestDetectorConfig:
    """Test DetectorConfig model."""
    
    def test_detector_config_defaults(self):
        """Test DetectorConfig with default values."""
        config = DetectorConfig()
        
        assert config.enabled_detectors == ["tls", "proxy", "browser", "network"]
        assert config.confidence_threshold == 0.7
        assert config.enable_batch_processing is True
        assert config.batch_size == 1000
        assert config.tls_config == {}
        assert config.proxy_config == {}
        assert config.browser_config == {}
        assert config.network_config == {}
    
    def test_detector_config_custom_values(self):
        """Test DetectorConfig with custom values."""
        tls_config = {"check_certificates": True}
        proxy_config = {"detect_transparent": False}
        
        config = DetectorConfig(
            enabled_detectors=["tls", "proxy"],
            confidence_threshold=0.9,
            enable_batch_processing=False,
            batch_size=500,
            tls_config=tls_config,
            proxy_config=proxy_config
        )
        
        assert config.enabled_detectors == ["tls", "proxy"]
        assert config.confidence_threshold == 0.9
        assert config.enable_batch_processing is False
        assert config.batch_size == 500
        assert config.tls_config == tls_config
        assert config.proxy_config == proxy_config
    
    def test_detector_config_confidence_validation(self):
        """Test DetectorConfig confidence threshold validation."""
        # Valid confidence values
        config = DetectorConfig(confidence_threshold=0.0)
        assert config.confidence_threshold == 0.0
        
        config = DetectorConfig(confidence_threshold=1.0)
        assert config.confidence_threshold == 1.0
        
        # Invalid confidence values - Pydantic raises ValidationError
        from pydantic import ValidationError
        
        with pytest.raises(ValidationError):
            DetectorConfig(confidence_threshold=-0.1)
        
        with pytest.raises(ValidationError):
            DetectorConfig(confidence_threshold=1.1)


class TestPluginConfig:
    """Test PluginConfig model."""
    
    def test_plugin_config_defaults(self):
        """Test PluginConfig with default values."""
        config = PluginConfig()
        
        assert config.enable_plugins is True
        assert config.plugin_directories == [Path("./plugins")]
        assert config.auto_discover is True
        assert config.enable_hot_reload is False
        assert config.max_plugin_memory_mb == 256
        assert config.plugin_timeout_seconds == 30.0
    
    def test_plugin_config_custom_values(self):
        """Test PluginConfig with custom values."""
        directories = [Path("/opt/plugins"), Path("/usr/plugins")]
        
        config = PluginConfig(
            enable_plugins=False,
            plugin_directories=directories,
            auto_discover=False,
            enable_hot_reload=True,
            max_plugin_memory_mb=512,
            plugin_timeout_seconds=60.0
        )
        
        assert config.enable_plugins is False
        assert config.plugin_directories == directories
        assert config.auto_discover is False
        assert config.enable_hot_reload is True
        assert config.max_plugin_memory_mb == 512
        assert config.plugin_timeout_seconds == 60.0
    
    @patch('pathlib.Path.mkdir')
    def test_plugin_config_directory_creation(self, mock_mkdir):
        """Test PluginConfig creates directories if they don't exist."""
        directories = ["/tmp/plugins1", "/tmp/plugins2"]
        config = PluginConfig(plugin_directories=directories)
        
        # Both directories should be created
        assert mock_mkdir.call_count == 2
        assert config.plugin_directories == [Path("/tmp/plugins1"), Path("/tmp/plugins2")]


class TestReportingConfig:
    """Test ReportingConfig model."""
    
    def test_reporting_config_defaults(self):
        """Test ReportingConfig with default values."""
        config = ReportingConfig()
        
        assert config.default_formats == [ReportFormat.JSON]
        assert config.enable_streaming_reports is True
        assert config.template_directory is None
        assert config.custom_templates == {}
        assert config.include_metadata is True
        assert config.include_execution_stats is True
    
    def test_reporting_config_custom_values(self):
        """Test ReportingConfig with custom values."""
        formats = [ReportFormat.JSON, ReportFormat.MARKDOWN]
        templates = {"custom": "template_content"}
        
        config = ReportingConfig(
            default_formats=formats,
            enable_streaming_reports=False,
            template_directory=Path("/tmp/templates"),
            custom_templates=templates,
            include_metadata=False,
            include_execution_stats=False
        )
        
        assert config.default_formats == [f.value for f in formats]
        assert config.enable_streaming_reports is False
        assert config.template_directory == Path("/tmp/templates")
        assert config.custom_templates == templates
        assert config.include_metadata is False
        assert config.include_execution_stats is False
    
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.mkdir')
    def test_reporting_config_template_directory_creation(self, mock_mkdir, mock_exists):
        """Test ReportingConfig creates template directory if it doesn't exist."""
        mock_exists.return_value = False
        
        config = ReportingConfig(template_directory="/tmp/templates")
        
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
        assert config.template_directory == Path("/tmp/templates")


class TestNetStealthConfig:
    """Test NetStealthConfig main configuration model."""
    
    def test_netstealth_config_defaults(self):
        """Test NetStealthConfig with default values."""
        config = NetStealthConfig()
        
        assert config.version == "2.0.0"
        assert isinstance(config.created_at, datetime)
        assert config.description == "NetStealth Analyzer Configuration"
        assert config.analysis_mode == AnalysisMode.BATCH
        assert config.target_service is None
        assert config.geography is None
        assert isinstance(config.logging, LoggingConfig)
        assert isinstance(config.performance, PerformanceConfig)
        assert isinstance(config.security, SecurityConfig)
        assert isinstance(config.output, OutputConfig)
        assert isinstance(config.filters, FilterConfig)
        assert isinstance(config.parsers, ParserConfig)
        assert isinstance(config.detectors, DetectorConfig)
        assert isinstance(config.plugins, PluginConfig)
        assert isinstance(config.reporting, ReportingConfig)
        assert config.custom == {}
    
    def test_netstealth_config_custom_values(self):
        """Test NetStealthConfig with custom values."""
        created_at = datetime.now(timezone.utc)
        
        config = NetStealthConfig(
            version="2.1.0",
            created_at=created_at,
            description="Custom Configuration",
            analysis_mode=AnalysisMode.PARALLEL,
            target_service="example.com",
            geography="US",
            custom={"key": "value"}
        )
        
        assert config.version == "2.1.0"
        assert config.created_at == created_at
        assert config.description == "Custom Configuration"
        assert config.analysis_mode == AnalysisMode.PARALLEL
        assert config.target_service == "example.com"
        assert config.geography == "US"
        assert config.custom == {"key": "value"}
    
    def test_netstealth_config_validation_parallel_mode(self):
        """Test NetStealthConfig validation for parallel mode."""
        # Valid parallel configuration
        config = NetStealthConfig(
            analysis_mode=AnalysisMode.PARALLEL,
            performance=PerformanceConfig(enable_parallel_processing=True)
        )
        assert config.analysis_mode == AnalysisMode.PARALLEL
        
        # Invalid parallel configuration - should raise error
        with pytest.raises(ValueError, match="Parallel analysis mode requires parallel processing"):
            NetStealthConfig(
                analysis_mode=AnalysisMode.PARALLEL,
                performance=PerformanceConfig(enable_parallel_processing=False)
            )
    
    def test_netstealth_config_validation_output_mode(self):
        """Test NetStealthConfig validation for output mode."""
        # Valid file output configuration
        config = NetStealthConfig(
            output=OutputConfig(
                mode=OutputMode.FILE,
                directory=Path("/tmp/output")
            )
        )
        assert config.output.mode == OutputMode.FILE
        
        # Console mode doesn't require directory validation
        config = NetStealthConfig(
            output=OutputConfig(mode=OutputMode.CONSOLE)
        )
        assert config.output.mode == OutputMode.CONSOLE
    
    def test_netstealth_config_component_methods(self):
        """Test NetStealthConfig component access methods."""
        config = NetStealthConfig()
        
        # Test get_component_config
        logging_config = config.get_component_config("logging")
        assert isinstance(logging_config, LoggingConfig)
        
        performance_config = config.get_component_config("performance")
        assert isinstance(performance_config, PerformanceConfig)
        
        # Test non-existent component
        assert config.get_component_config("nonexistent") is None
        
        # Test update_component_config
        config.update_component_config("logging", {"level": "DEBUG"})
        assert config.logging.level == LogLevel.DEBUG
    
    def test_netstealth_config_serialization(self):
        """Test NetStealthConfig serialization methods."""
        config = NetStealthConfig(target_service="example.com")
        
        # Test to_dict
        config_dict = config.to_dict()
        assert isinstance(config_dict, dict)
        assert config_dict["target_service"] == "example.com"
        assert "logging" in config_dict
        assert "performance" in config_dict
        
        # Test to_json
        config_json = config.to_json()
        assert isinstance(config_json, str)
        
        # Should be valid JSON
        parsed = json.loads(config_json)
        assert parsed["target_service"] == "example.com"
    
    def test_netstealth_config_extra_fields_forbidden(self):
        """Test NetStealthConfig forbids extra fields."""
        with pytest.raises(ValueError):
            NetStealthConfig(invalid_field="value")


class TestConfigurationManager:
    """Test ConfigurationManager class."""
    
    def test_configuration_manager_init(self):
        """Test ConfigurationManager initialization."""
        manager = ConfigurationManager()
        
        assert manager._config is None
        assert manager._config_file is None
        assert manager._watchers == []
    
    def test_configuration_manager_config_property(self):
        """Test ConfigurationManager config property."""
        manager = ConfigurationManager()
        
        # Should create default config on first access
        config = manager.config
        assert isinstance(config, NetStealthConfig)
        assert manager._config is config
        
        # Should return same config on subsequent access
        config2 = manager.config
        assert config2 is config
    
    def test_load_from_dict(self):
        """Test ConfigurationManager.load_from_dict."""
        manager = ConfigurationManager()
        
        config_data = {
            "target_service": "example.com",
            "analysis_mode": "parallel",
            "performance": {"enable_parallel_processing": True}
        }
        
        config = manager.load_from_dict(config_data)
        
        assert isinstance(config, NetStealthConfig)
        assert config.target_service == "example.com"
        assert config.analysis_mode == AnalysisMode.PARALLEL
        assert config.performance.enable_parallel_processing is True
    
    def test_load_from_dict_validation_error(self):
        """Test ConfigurationManager.load_from_dict with validation error."""
        manager = ConfigurationManager()
        
        # Invalid configuration
        config_data = {
            "analysis_mode": "parallel",
            "performance": {"enable_parallel_processing": False}
        }
        
        with pytest.raises(ConfigurationError, match="Configuration validation failed"):
            manager.load_from_dict(config_data)
    
    def test_load_from_file_json(self):
        """Test ConfigurationManager.load_from_file with JSON."""
        manager = ConfigurationManager()
        
        config_data = {
            "target_service": "example.com",
            "analysis_mode": "batch"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name
        
        try:
            config = manager.load_from_file(temp_path)
            
            assert isinstance(config, NetStealthConfig)
            assert config.target_service == "example.com"
            assert config.analysis_mode == AnalysisMode.BATCH
            assert manager._config_file == Path(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_load_from_file_not_found(self):
        """Test ConfigurationManager.load_from_file with non-existent file."""
        manager = ConfigurationManager()
        
        with pytest.raises(ConfigurationError, match="Configuration file not found"):
            manager.load_from_file("/nonexistent/config.json")
    
    def test_load_from_file_unsupported_format(self):
        """Test ConfigurationManager.load_from_file with unsupported format."""
        manager = ConfigurationManager()
        
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"some content")
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigurationError, match="Unsupported configuration file format"):
                manager.load_from_file(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_load_from_env(self):
        """Test ConfigurationManager.load_from_env."""
        manager = ConfigurationManager()
        
        # Set environment variables
        env_vars = {
            "NETSTEALTH_TARGET_SERVICE": "example.com",
            "NETSTEALTH_ANALYSIS_MODE": "batch",
            "NETSTEALTH_LOGGING__LEVEL": "DEBUG",
            "NETSTEALTH_PERFORMANCE__TIMEOUT_SECONDS": "600.0",
            "NETSTEALTH_FILTERS__MIN_CONFIDENCE": "0.8"
        }
        
        with patch.dict(os.environ, env_vars):
            config = manager.load_from_env()
            
            assert config.target_service == "example.com"
            assert config.analysis_mode == AnalysisMode.BATCH
            assert config.logging.level == LogLevel.DEBUG
            assert config.performance.timeout_seconds == 600.0
            assert config.filters.min_confidence == 0.8
    
    def test_convert_env_value(self):
        """Test ConfigurationManager._convert_env_value."""
        manager = ConfigurationManager()
        
        # Boolean conversion
        assert manager._convert_env_value("true") is True
        assert manager._convert_env_value("false") is False
        assert manager._convert_env_value("True") is True
        assert manager._convert_env_value("FALSE") is False
        
        # Number conversion
        assert manager._convert_env_value("42") == 42
        assert manager._convert_env_value("3.14") == 3.14
        
        # List conversion
        assert manager._convert_env_value("a,b,c") == ["a", "b", "c"]
        assert manager._convert_env_value("1, 2, 3") == ["1", "2", "3"]
        
        # String (default)
        assert manager._convert_env_value("hello") == "hello"
    
    def test_save_to_file_json(self):
        """Test ConfigurationManager.save_to_file with JSON."""
        manager = ConfigurationManager()
        config = NetStealthConfig(target_service="example.com")
        manager._config = config
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            manager.save_to_file(temp_path)
            
            # Verify file was written
            with open(temp_path, 'r') as f:
                saved_data = json.load(f)
            
            assert saved_data["target_service"] == "example.com"
        finally:
            os.unlink(temp_path)
    
    def test_save_to_file_no_path(self):
        """Test ConfigurationManager.save_to_file with no path specified."""
        manager = ConfigurationManager()
        
        with pytest.raises(ConfigurationError, match="No file path specified"):
            manager.save_to_file()
    
    def test_save_to_file_unsupported_format(self):
        """Test ConfigurationManager.save_to_file with unsupported format."""
        manager = ConfigurationManager()
        manager._config = NetStealthConfig()
        
        with pytest.raises(ConfigurationError, match="Unsupported file format"):
            manager.save_to_file("config.txt")
    
    def test_update_config(self):
        """Test ConfigurationManager.update_config."""
        manager = ConfigurationManager()
        
        # Initial config
        config = manager.config
        assert config.target_service is None
        
        # Update config
        updates = {
            "target_service": "example.com",
            "analysis_mode": "parallel",
            "performance": {"enable_parallel_processing": True}
        }
        
        manager.update_config(updates)
        
        assert manager.config.target_service == "example.com"
        assert manager.config.analysis_mode == AnalysisMode.PARALLEL
    
    def test_update_config_validation_error(self):
        """Test ConfigurationManager.update_config with validation error."""
        manager = ConfigurationManager()
        
        # Invalid update
        updates = {
            "analysis_mode": "parallel",
            "performance": {"enable_parallel_processing": False}
        }
        
        with pytest.raises(ConfigurationError, match="Configuration update validation failed"):
            manager.update_config(updates)
    
    def test_validate_config(self):
        """Test ConfigurationManager.validate_config."""
        manager = ConfigurationManager()
        
        # Valid config
        assert manager.validate_config() is True
        
        # Make config invalid by directly modifying
        manager._config = NetStealthConfig(target_service="example.com")
        assert manager.validate_config() is True
    
    def test_get_config_schema(self):
        """Test ConfigurationManager.get_config_schema."""
        manager = ConfigurationManager()
        
        schema = manager.get_config_schema()
        
        assert isinstance(schema, dict)
        assert "properties" in schema
        assert "target_service" in schema["properties"]
        assert "analysis_mode" in schema["properties"]
    
    def test_watchers(self):
        """Test ConfigurationManager watcher functionality."""
        manager = ConfigurationManager()
        
        # Mock watcher
        watcher = Mock()
        
        # Add watcher
        manager.add_watcher(watcher)
        assert watcher in manager._watchers
        
        # Update config should notify watcher
        manager.update_config({"target_service": "example.com"})
        watcher.assert_called_once_with(manager._config)
        
        # Remove watcher
        manager.remove_watcher(watcher)
        assert watcher not in manager._watchers
    
    def test_watcher_error_handling(self):
        """Test ConfigurationManager handles watcher errors gracefully."""
        manager = ConfigurationManager()
        
        # Mock watcher that raises exception
        def failing_watcher(config):
            raise Exception("Watcher error")
        
        manager.add_watcher(failing_watcher)
        
        # Should not raise exception
        manager.update_config({"target_service": "example.com"})
    
    def test_create_default_config_file(self):
        """Test ConfigurationManager.create_default_config_file."""
        manager = ConfigurationManager()
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            manager.create_default_config_file(temp_path)
            
            # Verify file was created with default config
            with open(temp_path, 'r') as f:
                saved_data = json.load(f)
            
            assert saved_data["version"] == "2.0.0"
            assert saved_data["analysis_mode"] == "batch"
        finally:
            os.unlink(temp_path)


class TestGlobalFunctions:
    """Test global configuration functions."""
    
    def test_get_config_manager(self):
        """Test get_config_manager function."""
        # Reset global manager
        import src.netstealth_analyzer.config as config_module
        config_module._config_manager = None
        
        manager1 = get_config_manager()
        assert isinstance(manager1, ConfigurationManager)
        
        # Should return same instance
        manager2 = get_config_manager()
        assert manager1 is manager2
    
    def test_get_config(self):
        """Test get_config function."""
        config = get_config()
        assert isinstance(config, NetStealthConfig)
    
    def test_load_config(self):
        """Test load_config function."""
        config_data = {"target_service": "example.com"}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name
        
        try:
            config = load_config(temp_path)
            assert isinstance(config, NetStealthConfig)
            assert config.target_service == "example.com"
        finally:
            os.unlink(temp_path)
    
    def test_save_config(self):
        """Test save_config function."""
        # Load a config first
        config_data = {"target_service": "example.com"}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path1 = f.name
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path2 = f.name
        
        try:
            # Load config
            load_config(temp_path1)
            
            # Save to new file
            save_config(temp_path2)
            
            # Verify saved file
            with open(temp_path2, 'r') as f:
                saved_data = json.load(f)
            
            assert saved_data["target_service"] == "example.com"
        finally:
            os.unlink(temp_path1)
            os.unlink(temp_path2)


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_create_sample_config(self):
        """Test create_sample_config function."""
        config = create_sample_config()
        
        assert isinstance(config, NetStealthConfig)
        assert config.target_service == "example.com"
        assert config.geography == "US"
        assert config.analysis_mode == AnalysisMode.BATCH
        assert config.logging.level == LogLevel.INFO
        assert config.logging.enable_file is True
        assert config.performance.max_concurrent_parsers == 3
        assert config.output.mode == OutputMode.BOTH
        assert config.filters.min_confidence == 0.7
    
    def test_validate_config_file_valid(self):
        """Test validate_config_file with valid file."""
        config_data = {"target_service": "example.com"}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name
        
        try:
            assert validate_config_file(temp_path) is True
        finally:
            os.unlink(temp_path)
    
    def test_validate_config_file_invalid(self):
        """Test validate_config_file with invalid file."""
        # Non-existent file
        assert validate_config_file("/nonexistent/config.json") is False
        
        # Invalid JSON
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json")
            temp_path = f.name
        
        try:
            assert validate_config_file(temp_path) is False
        finally:
            os.unlink(temp_path)


class TestConfigurationIntegration:
    """Integration tests for configuration system."""
    
    def test_full_configuration_lifecycle(self):
        """Test complete configuration lifecycle."""
        manager = ConfigurationManager()
        
        # Create custom config
        config_data = {
            "target_service": "example.com",
            "analysis_mode": "batch",
            "logging": {
                "level": "DEBUG",
                "enable_file": True
            },
            "performance": {
                "max_concurrent_parsers": 10,
                "timeout_seconds": 600.0
            },
            "filters": {
                "min_confidence": 0.8,
                "severity_levels": ["high", "critical"]
            }
        }
        
        # Load from dict
        config = manager.load_from_dict(config_data)
        
        # Verify loaded correctly
        assert config.target_service == "example.com"
        assert config.analysis_mode == AnalysisMode.BATCH
        assert config.logging.level == LogLevel.DEBUG
        assert config.logging.enable_file is True
        assert config.performance.max_concurrent_parsers == 10
        assert config.performance.timeout_seconds == 600.0
        assert config.filters.min_confidence == 0.8
        assert config.filters.severity_levels == ["high", "critical"]
        
        # Update configuration
        manager.update_config({
            "geography": "US",
            "output": {"mode": "file", "directory": "/tmp/reports"}
        })
        
        # Verify updates - need to get the updated config from manager
        updated_config = manager.config
        assert updated_config.geography == "US"
        assert updated_config.output.mode == OutputMode.FILE
        assert updated_config.output.directory == Path("/tmp/reports")
        
        # Test component access
        logging_config = config.get_component_config("logging")
        assert logging_config.level == LogLevel.DEBUG
        
        # Test serialization - use updated config
        config_dict = updated_config.to_dict()
        assert config_dict["target_service"] == "example.com"
        assert config_dict["geography"] == "US"
        
        config_json = updated_config.to_json()
        parsed = json.loads(config_json)
        assert parsed["target_service"] == "example.com"
    
    def test_environment_variable_integration(self):
        """Test environment variable integration."""
        manager = ConfigurationManager()
        
        env_vars = {
            "NETSTEALTH_TARGET_SERVICE": "env-example.com",
            "NETSTEALTH_ANALYSIS_MODE": "parallel",
            "NETSTEALTH_LOGGING__LEVEL": "ERROR",
            "NETSTEALTH_PERFORMANCE__ENABLE_PARALLEL_PROCESSING": "true",
            "NETSTEALTH_PERFORMANCE__MAX_CONCURRENT_PARSERS": "15",
            "NETSTEALTH_FILTERS__MIN_CONFIDENCE": "0.9",
            "NETSTEALTH_PARSERS__ENABLED_PARSERS": "har,mitmproxy"
        }
        
        with patch.dict(os.environ, env_vars):
            config = manager.load_from_env()
            
            assert config.target_service == "env-example.com"
            assert config.analysis_mode == AnalysisMode.PARALLEL
            assert config.logging.level == LogLevel.ERROR
            assert config.performance.enable_parallel_processing is True
            assert config.performance.max_concurrent_parsers == 15
            assert config.filters.min_confidence == 0.9
            assert config.parsers.enabled_parsers == ["har", "mitmproxy"]
    
    def test_file_format_compatibility(self):
        """Test different file format compatibility."""
        manager = ConfigurationManager()
        
        config_data = {
            "target_service": "format-test.com",
            "analysis_mode": "batch",
            "logging": {"level": "INFO"}
        }
        
        # Test JSON format
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            json_path = f.name
        
        try:
            config = manager.load_from_file(json_path)
            assert config.target_service == "format-test.com"
            assert config.analysis_mode == AnalysisMode.BATCH
            assert config.logging.level == LogLevel.INFO
        finally:
            os.unlink(json_path)
    
    def test_validation_edge_cases(self):
        """Test configuration validation edge cases."""
        # Test minimum valid configuration
        minimal_config = NetStealthConfig()
        assert minimal_config.version == "2.0.0"
        assert minimal_config.analysis_mode == AnalysisMode.BATCH
        
        # Test maximum configuration with all fields
        maximal_config = NetStealthConfig(
            target_service="maximal-test.com",
            geography="US",
            analysis_mode=AnalysisMode.PARALLEL,
            logging=LoggingConfig(
                level=LogLevel.DEBUG,
                enable_file=True,
                file_path=Path("/tmp/test.log"),
                max_file_size_mb=100,
                backup_count=10
            ),
            performance=PerformanceConfig(
                max_concurrent_parsers=20,
                max_concurrent_detectors=50,
                enable_parallel_processing=True,
                timeout_seconds=1800.0
            ),
            security=SecurityConfig(
                enable_plugin_sandboxing=True,
                allowed_plugin_paths=[Path("/opt/plugins")],
                enable_network_access=True,
                trusted_domains=["trusted.com"]
            ),
            custom={"custom_key": "custom_value"}
        )
        
        assert maximal_config.target_service == "maximal-test.com"
        assert maximal_config.geography == "US"
        assert maximal_config.analysis_mode == AnalysisMode.PARALLEL
        assert maximal_config.logging.level == LogLevel.DEBUG
        assert maximal_config.performance.max_concurrent_parsers == 20
        assert maximal_config.security.enable_plugin_sandboxing is True
        assert maximal_config.custom == {"custom_key": "custom_value"}
    
    def test_error_handling_robustness(self):
        """Test error handling robustness."""
        manager = ConfigurationManager()
        
        # Test invalid file paths
        with pytest.raises(ConfigurationError):
            manager.load_from_file("/invalid/path/config.json")
        
        # Test invalid configuration data
        with pytest.raises(ConfigurationError):
            manager.load_from_dict({"analysis_mode": "invalid_mode"})
        
        # Test saving without config - the config property creates a default config
        # so we need to test a different error condition
        manager._config = NetStealthConfig()
        with pytest.raises(ConfigurationError, match="No file path specified"):
            manager.save_to_file()
