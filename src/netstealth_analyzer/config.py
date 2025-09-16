"""
Configuration management for NetStealth Analyzer.

This module provides comprehensive configuration models, validation, and management
for all components in the analysis pipeline.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import os
from typing import Any, Dict, List, Optional, Union, Type, get_type_hints
from dataclasses import dataclass, field, fields
from pathlib import Path
from enum import Enum, auto
import logging
from datetime import datetime, timezone

from pydantic import BaseModel, Field, validator, model_validator
from pydantic import ValidationError as PydanticValidationError

from .core.errors import ConfigurationError, ValidationError, ErrorContext
from .core.interfaces import IConfigurable, ReportFormat, Priority
from .compatibility import load_toml, FeatureDetector

logger = logging.getLogger(__name__)


class LogLevel(str, Enum):
    """Logging levels for configuration."""
    
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class OutputMode(str, Enum):
    """Output modes for analysis results."""
    
    CONSOLE = "console"          # Output to console only
    FILE = "file"               # Output to file only
    BOTH = "both"               # Output to both console and file
    STREAM = "stream"           # Stream results as they're generated


class AnalysisMode(str, Enum):
    """Analysis execution modes."""
    
    BATCH = "batch"             # Process all files at once
    STREAMING = "streaming"     # Process files as a stream
    INCREMENTAL = "incremental" # Process files incrementally
    PARALLEL = "parallel"       # Process files in parallel


# ============================================================================
# Core Configuration Models
# ============================================================================

class LoggingConfig(BaseModel):
    """Configuration for logging system."""
    
    level: LogLevel = LogLevel.INFO
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[Path] = None
    max_file_size_mb: int = Field(default=10, ge=1, le=1000)
    backup_count: int = Field(default=5, ge=1, le=50)
    enable_console: bool = True
    enable_file: bool = False
    
    class Config:
        use_enum_values = True


class PerformanceConfig(BaseModel):
    """Configuration for performance settings."""
    
    max_concurrent_parsers: int = Field(default=5, ge=1, le=50)
    max_concurrent_detectors: int = Field(default=10, ge=1, le=100)
    max_memory_usage_mb: int = Field(default=1024, ge=128, le=8192)
    timeout_seconds: float = Field(default=300.0, ge=1.0, le=3600.0)
    enable_parallel_processing: bool = True
    batch_size: int = Field(default=100, ge=1, le=10000)
    
    @validator('timeout_seconds')
    def validate_timeout(cls, v):
        if v <= 0:
            raise ValueError('Timeout must be positive')
        return v


class SecurityConfig(BaseModel):
    """Configuration for security settings."""
    
    enable_plugin_sandboxing: bool = True
    allowed_plugin_paths: List[Path] = Field(default_factory=list)
    max_plugin_execution_time: float = Field(default=60.0, ge=1.0, le=300.0)
    enable_network_access: bool = False
    trusted_domains: List[str] = Field(default_factory=list)
    
    @validator('allowed_plugin_paths', pre=True)
    def validate_plugin_paths(cls, v):
        if isinstance(v, list):
            return [Path(p) if not isinstance(p, Path) else p for p in v]
        return v


class OutputConfig(BaseModel):
    """Configuration for output settings."""
    
    mode: OutputMode = OutputMode.CONSOLE
    directory: Path = Field(default=Path("./output"))
    filename_template: str = "netstealth_analysis_{timestamp}"
    default_format: ReportFormat = ReportFormat.JSON
    include_raw_data: bool = False
    include_statistics: bool = True
    compress_output: bool = False
    
    @validator('directory', pre=True)
    def validate_directory(cls, v):
        path = Path(v) if not isinstance(v, Path) else v
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    class Config:
        use_enum_values = True


class FilterConfig(BaseModel):
    """Configuration for filtering analysis results."""
    
    min_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    severity_levels: List[str] = Field(default_factory=lambda: ["medium", "high", "critical"])
    categories: List[str] = Field(default_factory=list)
    exclude_categories: List[str] = Field(default_factory=list)
    max_issues_per_category: Optional[int] = Field(default=None, ge=1)
    
    @validator('min_confidence')
    def validate_confidence(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError('Confidence must be between 0.0 and 1.0')
        return v


# ============================================================================
# Component-Specific Configurations
# ============================================================================

class ParserConfig(BaseModel):
    """Configuration for log parsers."""
    
    enabled_parsers: List[str] = Field(default_factory=lambda: ["har", "mitmproxy", "browser"])
    max_file_size_mb: int = Field(default=100, ge=1, le=1000)
    encoding: str = "utf-8"
    skip_invalid_entries: bool = True
    max_parse_errors: int = Field(default=10, ge=0, le=1000)
    enable_streaming: bool = True
    
    # Parser-specific settings
    har_config: Dict[str, Any] = Field(default_factory=dict)
    mitmproxy_config: Dict[str, Any] = Field(default_factory=dict)
    browser_config: Dict[str, Any] = Field(default_factory=dict)


class DetectorConfig(BaseModel):
    """Configuration for security detectors."""
    
    enabled_detectors: List[str] = Field(default_factory=lambda: ["tls", "proxy", "browser", "network"])
    confidence_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    enable_batch_processing: bool = True
    batch_size: int = Field(default=1000, ge=1, le=10000)
    
    # Detector-specific settings
    tls_config: Dict[str, Any] = Field(default_factory=dict)
    proxy_config: Dict[str, Any] = Field(default_factory=dict)
    browser_config: Dict[str, Any] = Field(default_factory=dict)
    network_config: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('confidence_threshold')
    def validate_confidence_threshold(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError('Confidence threshold must be between 0.0 and 1.0')
        return v


class PluginConfig(BaseModel):
    """Configuration for plugin system."""
    
    enable_plugins: bool = True
    plugin_directories: List[Path] = Field(default_factory=lambda: [Path("./plugins")])
    auto_discover: bool = True
    enable_hot_reload: bool = False
    max_plugin_memory_mb: int = Field(default=256, ge=16, le=2048)
    plugin_timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)
    
    @validator('plugin_directories', pre=True)
    def validate_plugin_directories(cls, v):
        if isinstance(v, list):
            paths = [Path(p) if not isinstance(p, Path) else p for p in v]
            # Create directories if they don't exist
            for path in paths:
                path.mkdir(parents=True, exist_ok=True)
            return paths
        return v


class ReportingConfig(BaseModel):
    """Configuration for report generation."""
    
    default_formats: List[ReportFormat] = Field(default_factory=lambda: [ReportFormat.JSON])
    enable_streaming_reports: bool = True
    template_directory: Optional[Path] = None
    custom_templates: Dict[str, str] = Field(default_factory=dict)
    include_metadata: bool = True
    include_execution_stats: bool = True
    
    @validator('template_directory', pre=True)
    def validate_template_directory(cls, v):
        if v is not None:
            path = Path(v) if not isinstance(v, Path) else v
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
            return path
        return v
    
    class Config:
        use_enum_values = True


# ============================================================================
# Main Configuration Model
# ============================================================================

class NetStealthConfig(BaseModel):
    """
    Main configuration model for NetStealth Analyzer.
    
    This is the root configuration that contains all component-specific
    configurations and global settings.
    """
    
    # Metadata
    version: str = "2.0.0"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = "NetStealth Analyzer Configuration"
    
    # Core settings
    analysis_mode: AnalysisMode = AnalysisMode.BATCH
    target_service: Optional[str] = None
    geography: Optional[str] = None
    
    # Component configurations
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    filters: FilterConfig = Field(default_factory=FilterConfig)
    parsers: ParserConfig = Field(default_factory=ParserConfig)
    detectors: DetectorConfig = Field(default_factory=DetectorConfig)
    plugins: PluginConfig = Field(default_factory=PluginConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    
    # Custom settings
    custom: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True
        validate_assignment = True
        extra = "forbid"  # Don't allow extra fields
    
    @model_validator(mode='before')
    @classmethod
    def validate_configuration(cls, values):
        """Validate the entire configuration for consistency."""
        # Validate analysis mode compatibility
        analysis_mode = values.get('analysis_mode')
        performance = values.get('performance', {})
        
        if analysis_mode == AnalysisMode.PARALLEL:
            if isinstance(performance, dict):
                if not performance.get('enable_parallel_processing', True):
                    raise ValueError("Parallel analysis mode requires parallel processing to be enabled")
            elif hasattr(performance, 'enable_parallel_processing'):
                if not performance.enable_parallel_processing:
                    raise ValueError("Parallel analysis mode requires parallel processing to be enabled")
        
        # Validate output configuration
        output = values.get('output', {})
        if isinstance(output, dict):
            mode = output.get('mode')
            directory = output.get('directory')
            if mode in [OutputMode.FILE, OutputMode.BOTH] and not directory:
                raise ValueError("File output mode requires output directory")
        
        return values
    
    def get_component_config(self, component_name: str) -> Optional[BaseModel]:
        """Get configuration for a specific component."""
        return getattr(self, component_name, None)
    
    def update_component_config(self, component_name: str, config: Dict[str, Any]) -> None:
        """Update configuration for a specific component."""
        if hasattr(self, component_name):
            current_config = getattr(self, component_name)
            if isinstance(current_config, BaseModel):
                # Update the existing config
                for key, value in config.items():
                    if hasattr(current_config, key):
                        setattr(current_config, key, value)
            else:
                # Replace with new config
                config_class = type(current_config)
                new_config = config_class(**config)
                setattr(self, component_name, new_config)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return self.dict()
    
    def to_json(self, indent: int = 2) -> str:
        """Convert configuration to JSON string."""
        return self.json(indent=indent)


# ============================================================================
# Configuration Manager
# ============================================================================

class ConfigurationManager:
    """
    Manages configuration loading, validation, and updates.
    
    Supports loading from files, environment variables, and programmatic updates.
    """
    
    def __init__(self):
        self._config: Optional[NetStealthConfig] = None
        self._config_file: Optional[Path] = None
        self._watchers: List[callable] = []
    
    @property
    def config(self) -> NetStealthConfig:
        """Get current configuration."""
        if self._config is None:
            self._config = NetStealthConfig()
        return self._config
    
    def load_from_file(self, file_path: Union[str, Path]) -> NetStealthConfig:
        """
        Load configuration from file.
        
        Supports TOML, JSON, and YAML formats.
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise ConfigurationError(f"Configuration file not found: {file_path}")
        
        try:
            if file_path.suffix.lower() == '.toml':
                data = load_toml(file_path)
            elif file_path.suffix.lower() == '.json':
                import json
                with file_path.open('r', encoding='utf-8') as f:
                    data = json.load(f)
            elif file_path.suffix.lower() in ['.yaml', '.yml']:
                try:
                    import yaml
                    with file_path.open('r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                except ImportError:
                    raise ConfigurationError("PyYAML not installed. Install with: pip install pyyaml")
            else:
                raise ConfigurationError(f"Unsupported configuration file format: {file_path.suffix}")
            
            self._config = NetStealthConfig(**data)
            self._config_file = file_path
            
            logger.info(f"Configuration loaded from {file_path}")
            self._notify_watchers()
            
            return self._config
            
        except PydanticValidationError as e:
            raise ConfigurationError(f"Configuration validation failed: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def load_from_dict(self, data: Dict[str, Any]) -> NetStealthConfig:
        """Load configuration from dictionary."""
        try:
            self._config = NetStealthConfig(**data)
            logger.info("Configuration loaded from dictionary")
            self._notify_watchers()
            return self._config
            
        except PydanticValidationError as e:
            raise ConfigurationError(f"Configuration validation failed: {e}")
    
    def load_from_env(self, prefix: str = "NETSTEALTH_") -> NetStealthConfig:
        """
        Load configuration from environment variables.
        
        Environment variables should be prefixed (default: NETSTEALTH_)
        and use double underscores for nested keys.
        
        Example: NETSTEALTH_LOGGING__LEVEL=DEBUG
        """
        env_data = {}
        
        for key, value in os.environ.items():
            if key.startswith(prefix):
                # Remove prefix and convert to nested dict
                config_key = key[len(prefix):].lower()
                keys = config_key.split('__')
                
                # Navigate/create nested structure
                current = env_data
                for k in keys[:-1]:
                    if k not in current:
                        current[k] = {}
                    current = current[k]
                
                # Convert value to appropriate type
                final_key = keys[-1]
                current[final_key] = self._convert_env_value(value)
        
        if env_data:
            # Merge with existing config or create new
            if self._config:
                config_dict = self._config.dict()
                config_dict.update(env_data)
                self._config = NetStealthConfig(**config_dict)
            else:
                self._config = NetStealthConfig(**env_data)
            
            logger.info("Configuration updated from environment variables")
            self._notify_watchers()
        
        return self.config
    
    def _convert_env_value(self, value: str) -> Any:
        """Convert environment variable string to appropriate type."""
        # Boolean conversion
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # Number conversion
        try:
            if '.' in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass
        
        # List conversion (comma-separated)
        if ',' in value:
            return [item.strip() for item in value.split(',')]
        
        # String (default)
        return value
    
    def save_to_file(self, file_path: Optional[Union[str, Path]] = None) -> None:
        """Save current configuration to file."""
        if file_path is None:
            file_path = self._config_file
        
        if file_path is None:
            raise ConfigurationError("No file path specified for saving configuration")
        
        file_path = Path(file_path)
        
        try:
            if file_path.suffix.lower() == '.toml':
                # Convert to TOML format
                try:
                    import toml
                    with file_path.open('w', encoding='utf-8') as f:
                        toml.dump(self.config.dict(), f)
                except ImportError:
                    raise ConfigurationError("toml not installed. Install with: pip install toml")
            
            elif file_path.suffix.lower() == '.json':
                with file_path.open('w', encoding='utf-8') as f:
                    f.write(self.config.to_json())
            
            elif file_path.suffix.lower() in ['.yaml', '.yml']:
                try:
                    import yaml
                    with file_path.open('w', encoding='utf-8') as f:
                        yaml.dump(self.config.dict(), f, default_flow_style=False)
                except ImportError:
                    raise ConfigurationError("PyYAML not installed. Install with: pip install pyyaml")
            
            else:
                raise ConfigurationError(f"Unsupported file format: {file_path.suffix}")
            
            logger.info(f"Configuration saved to {file_path}")
            
        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration: {e}")
    
    def update_config(self, updates: Dict[str, Any]) -> None:
        """Update configuration with new values."""
        try:
            config_dict = self.config.dict()
            config_dict.update(updates)
            self._config = NetStealthConfig(**config_dict)
            
            logger.info("Configuration updated")
            self._notify_watchers()
            
        except PydanticValidationError as e:
            raise ConfigurationError(f"Configuration update validation failed: {e}")
    
    def validate_config(self) -> bool:
        """Validate current configuration."""
        try:
            # Re-create config to trigger validation
            NetStealthConfig(**self.config.dict())
            return True
        except PydanticValidationError:
            return False
    
    def get_config_schema(self) -> Dict[str, Any]:
        """Get JSON schema for configuration."""
        return NetStealthConfig.schema()
    
    def add_watcher(self, callback: callable) -> None:
        """Add a callback to be notified when configuration changes."""
        self._watchers.append(callback)
    
    def remove_watcher(self, callback: callable) -> None:
        """Remove a configuration change watcher."""
        if callback in self._watchers:
            self._watchers.remove(callback)
    
    def _notify_watchers(self) -> None:
        """Notify all watchers of configuration changes."""
        for watcher in self._watchers:
            try:
                watcher(self._config)
            except Exception as e:
                logger.error(f"Error in configuration watcher: {e}")
    
    def create_default_config_file(self, file_path: Union[str, Path]) -> None:
        """Create a default configuration file."""
        file_path = Path(file_path)
        
        # Create default config
        default_config = NetStealthConfig()
        
        # Save to file
        self._config = default_config
        self.save_to_file(file_path)
        
        logger.info(f"Default configuration file created at {file_path}")


# ============================================================================
# Global Configuration Instance
# ============================================================================

# Global configuration manager instance
_config_manager: Optional[ConfigurationManager] = None


def get_config_manager() -> ConfigurationManager:
    """Get the global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigurationManager()
    return _config_manager


def get_config() -> NetStealthConfig:
    """Get the current global configuration."""
    return get_config_manager().config


def load_config(file_path: Union[str, Path]) -> NetStealthConfig:
    """Load configuration from file."""
    return get_config_manager().load_from_file(file_path)


def save_config(file_path: Optional[Union[str, Path]] = None) -> None:
    """Save current configuration to file."""
    get_config_manager().save_to_file(file_path)


# ============================================================================
# Configuration Utilities
# ============================================================================

def create_sample_config() -> NetStealthConfig:
    """Create a sample configuration with common settings."""
    return NetStealthConfig(
        target_service="example.com",
        geography="US",
        analysis_mode=AnalysisMode.BATCH,
        logging=LoggingConfig(
            level=LogLevel.INFO,
            enable_file=True,
            file_path=Path("./logs/netstealth.log")
        ),
        performance=PerformanceConfig(
            max_concurrent_parsers=3,
            max_concurrent_detectors=5,
            timeout_seconds=600.0
        ),
        output=OutputConfig(
            mode=OutputMode.BOTH,
            directory=Path("./reports"),
            default_format=ReportFormat.MARKDOWN
        ),
        filters=FilterConfig(
            min_confidence=0.7,
            severity_levels=["high", "critical"]
        )
    )


def validate_config_file(file_path: Union[str, Path]) -> bool:
    """Validate a configuration file without loading it."""
    try:
        manager = ConfigurationManager()
        manager.load_from_file(file_path)
        return True
    except Exception:
        return False


# Export public API
__all__ = [
    # Enums
    'LogLevel',
    'OutputMode',
    'AnalysisMode',
    
    # Configuration models
    'LoggingConfig',
    'PerformanceConfig',
    'SecurityConfig',
    'OutputConfig',
    'FilterConfig',
    'ParserConfig',
    'DetectorConfig',
    'PluginConfig',
    'ReportingConfig',
    'NetStealthConfig',
    
    # Manager
    'ConfigurationManager',
    
    # Global functions
    'get_config_manager',
    'get_config',
    'load_config',
    'save_config',
    
    # Utilities
    'create_sample_config',
    'validate_config_file',
]
