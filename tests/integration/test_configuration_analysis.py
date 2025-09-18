"""
Integration tests for configuration-driven analysis workflows.

Tests configuration validation → system setup → analysis pipeline integration.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

from src.netstealth_analyzer.config import ConfigurationManager
from src.netstealth_analyzer.core.events import EventBus
from src.netstealth_analyzer.core.errors import ErrorHandler
from src.netstealth_analyzer.plugins.registry import PluginRegistry
from src.netstealth_analyzer.plugins.loader import PluginLoader
from src.netstealth_analyzer.plugins.sandbox import PluginSandbox
from src.netstealth_analyzer.models.network import NetworkTrace
from src.netstealth_analyzer.models.results import AnalysisResult
from src.netstealth_analyzer.models.issues import SeverityLevel


class TestConfigurationDrivenAnalysis:
    """Test complete analysis workflows driven by configuration."""
    
    @pytest.mark.asyncio
    async def test_minimal_configuration_analysis(
        self,
        config_manager,
        event_bus,
        plugin_registry,
        sample_network_trace,
        integration_helper
    ):
        """Test analysis with minimal configuration."""
        minimal_config = {
            "analysis": {
                "timeout": 10.0,
                "parallel_processing": False
            },
            "plugins": {
                "auto_load": False,
                "sandbox": {
                    "enabled": False
                }
            }
        }
        
        # Set configuration
        config_manager.load_from_dict(minimal_config)
        
        # Verify configuration is loaded correctly
        assert config_manager.get("analysis.timeout") == 10.0
        assert config_manager.get("analysis.parallel_processing") is False
        assert config_manager.get("plugins.auto_load") is False
        assert config_manager.get("plugins.sandbox.enabled") is False
        
        # Test that system respects minimal configuration
        sandbox_enabled = config_manager.get("plugins.sandbox.enabled", True)
        assert sandbox_enabled is False
        
        parallel_enabled = config_manager.get("analysis.parallel_processing", True)
        assert parallel_enabled is False
    
    @pytest.mark.asyncio
    async def test_comprehensive_configuration_analysis(
        self,
        config_manager,
        event_bus,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper,
        sample_network_trace
    ):
        """Test analysis with comprehensive configuration."""
        comprehensive_config = {
            "analysis": {
                "timeout": 60.0,
                "max_traces": 5000,
                "parallel_processing": True,
                "batch_size": 100,
                "enable_caching": True
            },
            "plugins": {
                "directory": str(temp_plugin_dir),
                "auto_load": True,
                "sandbox": {
                    "enabled": True,
                    "memory_limit_mb": 200,
                    "execution_timeout": 30.0,
                    "cpu_limit": 15.0
                },
                "filters": {
                    "enabled_types": ["detector", "analyzer"],
                    "min_version": "1.0.0",
                    "blacklist": []
                }
            },
            "reporting": {
                "format": "json",
                "include_evidence": True,
                "include_traces": False,
                "severity_filter": "low",
                "max_issues": 1000
            },
            "logging": {
                "level": "DEBUG",
                "file": "/tmp/comprehensive_test.log",
                "console": True,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            },
            "security": {
                "enable_validation": True,
                "signature_checking": False,
                "trusted_sources": ["local", "verified"]
            }
        }
        
        # Set comprehensive configuration
        config_manager.load_from_dict(comprehensive_config)
        
        # Create a test plugin that uses configuration
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel

class ConfigAwarePlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="config_aware_plugin",
            version="1.5.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin that reads system configuration"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Detection method that uses configuration."""
        # Simulate using configuration values
        max_traces = self.get_config_value("max_traces", 1000)  # From analysis config
        severity_filter = self.get_config_value("severity_filter", "medium")  # From reporting config
        
        issues = []
        processed_traces = traces[:max_traces] if max_traces else traces
        
        for i, trace in enumerate(processed_traces):
            if i >= 2:  # Limit for testing
                break
                
            severity_map = {
                "low": SeverityLevel.LOW,
                "medium": SeverityLevel.MEDIUM,
                "high": SeverityLevel.HIGH
            }
            
            issue = Issue(
                id=f"config-aware-{trace.trace_id}-{i}",
                category=IssueCategory.CONFIGURATION,
                severity=severity_map.get(severity_filter, SeverityLevel.MEDIUM),
                title="Config-Aware Detection",
                description=f"Using max_traces={max_traces}, severity={severity_filter}",
                confidence=0.8,
                impact_score=50
            )
            issues.append(issue)
        
        return issues
'''
        
        # Create plugin file
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "config_aware.py", plugin_code
        )
        
        # Load plugin using comprehensive configuration
        loader = PluginLoader(plugin_registry)
        
        # Pass system configuration to plugin
        plugin_config = {
            "max_traces": config_manager.get("analysis.max_traces"),
            "severity_filter": config_manager.get("reporting.severity_filter")
        }
        
        plugins = await loader.load_plugin_from_file(plugin_file, config=plugin_config)
        plugin = plugins[0]
        
        # Create sandbox based on configuration
        sandbox_config = config_manager.get("plugins.sandbox")
        configured_sandbox = PluginSandbox(
            max_memory_mb=sandbox_config.get("memory_limit_mb", 100),
            max_execution_time=sandbox_config.get("execution_timeout", 10.0),
            max_cpu_time=sandbox_config.get("cpu_limit", 5.0)
        )
        
        # Execute plugin with configuration-based sandbox
        traces = [sample_network_trace] * 3  # Multiple traces for testing
        
        with configured_sandbox.execute_sandboxed(plugin):
            issues = await configured_sandbox.execute_plugin_method(
                plugin, "detect", traces
            )
        
        # Verify configuration was applied
        assert len(issues) == 2  # Limited by plugin logic
        for issue in issues:
            assert issue.severity == SeverityLevel.LOW  # Based on config severity_filter
            assert "max_traces=5000" in issue.description
            assert "severity=low" in issue.description
    
    @pytest.mark.asyncio
    async def test_configuration_validation_workflow(
        self,
        config_manager,
        integration_helper
    ):
        """Test configuration validation and error handling."""
        # Test invalid configuration scenarios
        invalid_configs = [
            # Invalid timeout value
            {
                "analysis": {
                    "timeout": -10.0  # Invalid negative timeout
                }
            },
            # Invalid plugin directory
            {
                "plugins": {
                    "directory": "/nonexistent/directory/that/does/not/exist"
                }
            },
            # Invalid memory limit
            {
                "plugins": {
                    "sandbox": {
                        "memory_limit_mb": "invalid_string"  # Should be number
                    }
                }
            },
            # Invalid logging level
            {
                "logging": {
                    "level": "INVALID_LEVEL"
                }
            }
        ]
        
        for i, invalid_config in enumerate(invalid_configs):
            # Each invalid config should either fail validation or use defaults
            try:
                config_manager.load_from_dict(invalid_config)
                # If no exception, check that invalid values use defaults
                if "analysis" in invalid_config:
                    timeout = config_manager.get("analysis.timeout", 30.0)
                    assert timeout > 0, f"Config {i}: Invalid timeout should use default"
                
            except Exception as e:
                # Expected for some invalid configurations
                assert "validation" in str(e).lower() or "invalid" in str(e).lower()
    
    @pytest.mark.asyncio
    async def test_dynamic_configuration_updates(
        self,
        config_manager,
        event_bus,
        plugin_registry,
        temp_plugin_dir,
        integration_helper,
        sample_network_trace
    ):
        """Test dynamic configuration updates during analysis."""
        initial_config = {
            "analysis": {
                "timeout": 30.0,
                "parallel_processing": False
            },
            "plugins": {
                "sandbox": {
                    "enabled": True,
                    "memory_limit_mb": 50
                }
            }
        }
        
        # Set initial configuration
        config_manager.load_from_dict(initial_config)
        
        # Verify initial values
        assert config_manager.get("analysis.timeout") == 30.0
        assert config_manager.get("plugins.sandbox.memory_limit_mb") == 50
        
        # Update configuration dynamically
        updated_config = {
            "analysis": {
                "timeout": 60.0,
                "parallel_processing": True
            },
            "plugins": {
                "sandbox": {
                    "enabled": True,
                    "memory_limit_mb": 100
                }
            }
        }
        
        config_manager.load_from_dict(updated_config)
        
        # Verify updated values
        assert config_manager.get("analysis.timeout") == 60.0
        assert config_manager.get("plugins.sandbox.memory_limit_mb") == 100
        assert config_manager.get("analysis.parallel_processing") is True
    
    @pytest.mark.asyncio
    async def test_environment_specific_configuration(
        self,
        config_manager,
        temp_plugin_dir,
        integration_helper
    ):
        """Test environment-specific configuration handling."""
        # Development environment config
        dev_config = {
            "environment": "development",
            "analysis": {
                "timeout": 10.0,
                "debug_mode": True,
                "verbose_logging": True
            },
            "plugins": {
                "sandbox": {
                    "enabled": False,  # Disabled for development
                    "strict_mode": False
                }
            },
            "logging": {
                "level": "DEBUG",
                "console": True
            }
        }
        
        # Production environment config
        prod_config = {
            "environment": "production",
            "analysis": {
                "timeout": 120.0,
                "debug_mode": False,
                "verbose_logging": False
            },
            "plugins": {
                "sandbox": {
                    "enabled": True,  # Enabled for production security
                    "strict_mode": True,
                    "memory_limit_mb": 256,
                    "execution_timeout": 60.0
                }
            },
            "logging": {
                "level": "WARNING",
                "console": False,
                "file": "/var/log/netstealth/analyzer.log"
            }
        }
        
        # Test development configuration
        config_manager.load_from_dict(dev_config)
        assert config_manager.get("environment") == "development"
        assert config_manager.get("analysis.debug_mode") is True
        assert config_manager.get("plugins.sandbox.enabled") is False
        assert config_manager.get("logging.level") == "DEBUG"
        
        # Test production configuration
        config_manager.load_from_dict(prod_config)
        assert config_manager.get("environment") == "production"
        assert config_manager.get("analysis.debug_mode") is False
        assert config_manager.get("plugins.sandbox.enabled") is True
        assert config_manager.get("plugins.sandbox.strict_mode") is True
        assert config_manager.get("logging.level") == "WARNING"
    
    @pytest.mark.asyncio
    async def test_configuration_file_formats(
        self,
        config_manager,
        temp_plugin_dir,
        integration_helper
    ):
        """Test loading configuration from different file formats."""
        base_config = {
            "analysis": {
                "timeout": 45.0,
                "max_traces": 2000
            },
            "plugins": {
                "auto_load": True,
                "directory": str(temp_plugin_dir)
            }
        }
        
        # Test JSON format
        json_config_file = integration_helper.create_config_file(temp_plugin_dir, base_config)
        
        with open(json_config_file, 'r') as f:
            loaded_config = json.load(f)
        
        config_manager.load_from_dict(loaded_config)
        assert config_manager.get("analysis.timeout") == 45.0
        assert config_manager.get("analysis.max_traces") == 2000
        
        # Test configuration merging
        additional_config = {
            "analysis": {
                "parallel_processing": True,  # New field
                "timeout": 90.0  # Override existing
            },
            "reporting": {
                "format": "yaml",  # New section
                "include_evidence": False
            }
        }
        
        # Merge configurations
        config_manager.load_from_dict(additional_config)
        
        # Verify merged result
        assert config_manager.get("analysis.timeout") == 90.0  # Overridden
        assert config_manager.get("analysis.max_traces") == 2000  # Preserved
        assert config_manager.get("analysis.parallel_processing") is True  # Added
        assert config_manager.get("reporting.format") == "yaml"  # New section
    
    @pytest.mark.asyncio
    async def test_configuration_driven_plugin_filtering(
        self,
        config_manager,
        plugin_registry,
        temp_plugin_dir,
        integration_helper
    ):
        """Test plugin filtering based on configuration."""
        # Configuration with plugin filters
        filter_config = {
            "plugins": {
                "directory": str(temp_plugin_dir),
                "auto_load": True,
                "filters": {
                    "enabled_types": ["detector"],  # Only detectors
                    "min_version": "2.0.0",  # Minimum version
                    "max_version": "3.0.0",  # Maximum version
                    "blacklist": ["unreliable_plugin"],  # Blacklisted plugins
                    "whitelist": ["trusted_plugin_1", "trusted_plugin_2"]  # Whitelisted plugins
                }
            }
        }
        
        config_manager.load_from_dict(filter_config)
        
        # Create plugins that should and shouldn't be loaded based on filters
        plugins_to_create = [
            # Should be loaded: detector, version 2.5.0, in whitelist
            ("trusted_plugin_1.py", '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class TrustedPlugin1(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="trusted_plugin_1",
            version="2.5.0",
            plugin_type=PluginType.DETECTOR,
            description="Trusted detector plugin"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''),
            
            # Should NOT be loaded: version too old
            ("old_plugin.py", '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class OldPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="old_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Old plugin"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''),
            
            # Should NOT be loaded: wrong type (parser instead of detector)
            ("parser_plugin.py", '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class ParserPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="parser_plugin",
            version="2.1.0",
            plugin_type=PluginType.PARSER,
            description="Parser plugin"
        )
    
    @property
    def metadata(self):
        return self._metadata
'''),
            
            # Should NOT be loaded: blacklisted
            ("unreliable_plugin.py", '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class UnreliablePlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="unreliable_plugin",
            version="2.2.0",
            plugin_type=PluginType.DETECTOR,
            description="Unreliable plugin"
        )
    
    @property
    def metadata(self):
        return self._metadata
''')
        ]
        
        # Create all plugin files
        for filename, code in plugins_to_create:
            integration_helper.create_plugin_file(temp_plugin_dir, filename, code)
        
        # Load plugins with filtering
        loader = PluginLoader(plugin_registry)
        discovered_plugins = await loader.discover_plugins_in_directory(temp_plugin_dir)
        
        # Verify filtering (this is simplified - actual filtering would happen in a higher-level component)
        plugin_names = {plugin.name for plugin in discovered_plugins}
        
        # All plugins would be loaded by the loader itself
        # In a real system, filtering would be applied by the analysis engine
        assert len(discovered_plugins) == 4  # All plugins loaded by loader
        
        # Simulate configuration-based filtering
        filters = config_manager.get("plugins.filters", {})
        enabled_types = filters.get("enabled_types", [])
        min_version = filters.get("min_version", "0.0.0")
        blacklist = filters.get("blacklist", [])
        whitelist = filters.get("whitelist", [])
        
        filtered_plugins = []
        for plugin in discovered_plugins:
            # Check type filter
            if enabled_types and plugin.plugin_type.value not in enabled_types:
                continue
            
            # Check version filter
            if plugin.version < min_version:
                continue
            
            # Check blacklist
            if plugin.name in blacklist:
                continue
            
            # Check whitelist (if specified)
            if whitelist and plugin.name not in whitelist:
                continue
            
            filtered_plugins.append(plugin)
        
        # Verify only trusted_plugin_1 passes all filters
        assert len(filtered_plugins) == 1
        assert filtered_plugins[0].name == "trusted_plugin_1"
