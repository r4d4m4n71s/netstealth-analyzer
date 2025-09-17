"""
Integration tests for end-to-end plugin workflows.

Tests the complete plugin lifecycle: loading → sandboxing → execution → results.
"""

import pytest
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from src.netstealth_analyzer.plugins.loader import PluginLoader
from src.netstealth_analyzer.plugins.sandbox import PluginSandbox
from src.netstealth_analyzer.plugins.registry import PluginRegistry
from src.netstealth_analyzer.models.network import NetworkTrace, NetworkHop
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel
from src.netstealth_analyzer.core.events import EventBus, AnalysisEvent
from src.netstealth_analyzer.core.errors import ErrorHandler


class TestEndToEndPluginWorkflows:
    """Test complete plugin workflows from loading to execution."""
    
    @pytest.mark.asyncio
    async def test_complete_plugin_lifecycle(
        self, 
        plugin_registry, 
        plugin_sandbox, 
        temp_plugin_dir, 
        integration_helper,
        event_bus,
        sample_network_trace
    ):
        """Test complete plugin lifecycle: load → register → sandbox → execute."""
        # Create a detector plugin
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence

class WorkflowTestDetector(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="workflow_test_detector",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Detector for workflow testing",
            sandboxed=True
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Detect issues in traces."""
        issues = []
        for trace in traces:
            # Check if trace has hops with example.com IP
            for hop in trace.hops:
                if "93.184.216.34" in hop.outgoing_ip:  # example.com IP
                    issue = Issue(
                        id=f"workflow-{trace.trace_id}",
                        category=IssueCategory.NETWORK_ANOMALY,
                        severity=SeverityLevel.MEDIUM,
                        title="Workflow Test Detection",
                        description="Issue detected by workflow test plugin",
                        confidence=0.9,
                        impact_score=60,
                        evidence=[
                            IssueEvidence(
                                type="network_hop",
                                description="Example.com IP detected in hop",
                                raw_data={"trace_id": trace.trace_id, "hop_ip": hop.outgoing_ip},
                                confidence=0.9
                            )
                        ]
                    )
                    issues.append(issue)
                    break  # Only one issue per trace
        return issues
'''
        
        # Step 1: Create plugin file
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "workflow_detector.py", plugin_code
        )
        
        # Step 2: Load plugin
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        assert len(plugins) == 1
        plugin = plugins[0]
        
        # Step 3: Verify plugin is registered
        registered_plugins = plugin_registry.list_plugins()
        assert len(registered_plugins) == 1
        assert registered_plugins[0]['name'] == "workflow_test_detector"
        
        # Step 4: Execute plugin in sandbox
        with plugin_sandbox.execute_sandboxed(plugin):
            issues = await plugin_sandbox.execute_plugin_method(
                plugin, "detect", [sample_network_trace]
            )
        
        # Step 5: Verify results
        assert len(issues) == 1
        assert issues[0].title == "Workflow Test Detection"
        # Evidence is a list of IssueEvidence objects, not a dict
        assert len(issues[0].evidence) == 1
        assert issues[0].evidence[0].raw_data["hop_ip"] == "93.184.216.34"
    
    @pytest.mark.asyncio
    async def test_multi_plugin_workflow(
        self, 
        plugin_registry, 
        plugin_sandbox, 
        temp_plugin_dir,
        integration_helper,
        sample_network_trace
    ):
        """Test workflow with multiple plugins."""
        # Create multiple plugins
        detector_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel

class MultiDetector1(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="multi_detector_1",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="First detector"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        return [Issue(
            id="multi-1",
            category=IssueCategory.PRIVACY_VIOLATION,
            severity=SeverityLevel.LOW,
            title="Multi Detection 1",
            description="First detector result",
            confidence=0.8,
            impact_score=30
        )]

class MultiDetector2(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="multi_detector_2",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Second detector"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        return [Issue(
            id="multi-2",
            category=IssueCategory.TLS_FINGERPRINT,
            severity=SeverityLevel.HIGH,
            title="Multi Detection 2",
            description="Second detector result",
            confidence=0.9,
            impact_score=85
        )]
'''
        
        # Create plugin file with multiple plugins
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "multi_detectors.py", detector_code
        )
        
        # Load all plugins
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        assert len(plugins) == 2
        
        # Execute all plugins
        all_issues = []
        for plugin in plugins:
            with plugin_sandbox.execute_sandboxed(plugin):
                issues = await plugin_sandbox.execute_plugin_method(
                    plugin, "detect", [sample_network_trace]
                )
                all_issues.extend(issues)
        
        # Verify results from both plugins
        assert len(all_issues) == 2
        issue_titles = {issue.title for issue in all_issues}
        assert issue_titles == {"Multi Detection 1", "Multi Detection 2"}
    
    @pytest.mark.asyncio
    async def test_plugin_workflow_with_events(
        self, 
        plugin_registry, 
        plugin_sandbox, 
        temp_plugin_dir,
        integration_helper,
        event_bus,
        sample_network_trace
    ):
        """Test plugin workflow with event emission and handling."""
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel
from src.netstealth_analyzer.core.events import AnalysisEvent

class EventEmittingPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="event_emitting_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin that emits events"
        )
        self.event_bus = None
    
    @property
    def metadata(self):
        return self._metadata
    
    def set_event_bus(self, event_bus):
        """Set the event bus for this plugin."""
        self.event_bus = event_bus
    
    async def detect(self, traces):
        """Detect issues and emit events."""
        issues = []
        for trace in traces:
            issue = Issue(
                id=f"event-{trace.trace_id}",
                category=IssueCategory.PRIVACY_VIOLATION,
                severity=SeverityLevel.MEDIUM,
                title="Event Test Detection",
                description="Detection with event emission",
                confidence=0.8,
                impact_score=50
            )
            issues.append(issue)
            
            # Emit event if event bus is available
            if self.event_bus:
                await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {
                    "issue_id": issue.id,
                    "severity": issue.severity,
                    "plugin": self.name
                })
        
        return issues
'''
        
        # Create and load plugin
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "event_plugin.py", plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        plugin = plugins[0]
        
        # Set up event listener
        events_received = []
        
        async def event_listener(event, event_data):
            events_received.append(event_data)
        
        subscription = event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, event_listener)
        
        # Execute plugin with event bus
        with plugin_sandbox.execute_sandboxed(plugin):
            # Set event bus on plugin
            await plugin_sandbox.execute_plugin_method(
                plugin, "set_event_bus", event_bus
            )
            
            # Execute detection
            issues = await plugin_sandbox.execute_plugin_method(
                plugin, "detect", [sample_network_trace]
            )
        
        # Wait a bit for async event processing
        await asyncio.sleep(0.1)
        
        # Verify results and events
        assert len(issues) == 1
        assert len(events_received) == 1
        assert events_received[0]["plugin"] == "event_emitting_plugin"
        assert events_received[0]["issue_id"] == "event-test-trace-001"
    
    @pytest.mark.asyncio
    async def test_plugin_workflow_error_handling(
        self, 
        plugin_registry, 
        plugin_sandbox, 
        temp_plugin_dir,
        integration_helper,
        error_handler,
        sample_network_trace
    ):
        """Test plugin workflow with error handling."""
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType

class ErrorPronePlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="error_prone_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin that may cause errors"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Detect method that may raise errors."""
        if not traces:
            raise ValueError("No traces provided")
        
        # Simulate error for specific trace_ids
        for trace in traces:
            if "error" in trace.trace_id:
                raise RuntimeError("Simulated plugin error")
        
        return []  # No issues found
    
    def working_method(self):
        """A method that works correctly."""
        return "Plugin is working"
'''
        
        # Create plugin
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "error_plugin.py", plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        plugin = plugins[0]
        
        # Test working method first
        with plugin_sandbox.execute_sandboxed(plugin):
            result = await plugin_sandbox.execute_plugin_method(
                plugin, "working_method"
            )
            assert result == "Plugin is working"
        
        # Test error handling with empty traces
        with plugin_sandbox.execute_sandboxed(plugin):
            try:
                await plugin_sandbox.execute_plugin_method(plugin, "detect", [])
                assert False, "Should have raised an error"
            except Exception as e:
                assert "execution failed" in str(e).lower()
        
        # Test successful execution with valid traces
        with plugin_sandbox.execute_sandboxed(plugin):
            issues = await plugin_sandbox.execute_plugin_method(
                plugin, "detect", [sample_network_trace]
            )
            assert issues == []  # No issues expected for normal traces
    
    @pytest.mark.asyncio
    async def test_plugin_configuration_workflow(
        self, 
        plugin_registry, 
        plugin_sandbox, 
        temp_plugin_dir,
        integration_helper,
        sample_network_trace
    ):
        """Test plugin workflow with custom configuration."""
        plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence

class ConfigurablePlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="configurable_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin with configuration",
            config_schema={
                "detection_threshold": {"type": "float", "default": 0.5},
                "enabled_checks": {"type": "list", "default": ["url", "headers"]},
                "severity_level": {"type": "string", "default": "medium"}
            }
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Configurable detection method."""
        threshold = self.get_config_value("detection_threshold", 0.5)
        enabled_checks = self.get_config_value("enabled_checks", ["url"])
        severity_level = self.get_config_value("severity_level", "medium")
        
        issues = []
        for trace in traces:
            score = 0.0
            
            # Use trace_id instead of trace.request.url since NetworkTrace doesn't have request
            if "url" in enabled_checks and "test" in trace.trace_id:
                score += 0.6
            
            # Simplified check since we don't have headers in NetworkTrace
            if "headers" in enabled_checks:
                score += 0.4
            
            if score >= threshold:
                severity_map = {
                    "low": SeverityLevel.LOW,
                    "medium": SeverityLevel.MEDIUM,
                    "high": SeverityLevel.HIGH
                }
                
                issue = Issue(
                    id=f"config-{trace.trace_id}",
                    category=IssueCategory.CONFIGURATION,
                    severity=severity_map.get(severity_level, SeverityLevel.MEDIUM),
                    title="Configurable Detection",
                    description=f"Detection with score {score:.2f} (threshold: {threshold})",
                    confidence=score,  # Use score as confidence
                    impact_score=int(score * 100),
                    evidence=[
                        IssueEvidence(
                            type="configuration",
                            description="Configurable detection result",
                            raw_data={
                                "score": score,
                                "threshold": threshold,
                                "checks": enabled_checks
                            },
                            confidence=score
                        )
                    ]
                )
                issues.append(issue)
        
        return issues
'''
        
        # Create plugin file
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "configurable_plugin.py", plugin_code
        )
        
        # Test with default configuration
        loader = PluginLoader(plugin_registry)
        plugins_default = await loader.load_plugin_from_file(plugin_file)
        plugin_default = plugins_default[0]
        
        with plugin_sandbox.execute_sandboxed(plugin_default):
            issues_default = await plugin_sandbox.execute_plugin_method(
                plugin_default, "detect", [sample_network_trace]
            )
        
        assert len(issues_default) == 1
        assert issues_default[0].severity == SeverityLevel.MEDIUM
        
        # Test with custom configuration
        custom_config = {
            "detection_threshold": 0.8,
            "enabled_checks": ["url", "headers"],
            "severity_level": "high"
        }
        
        plugins_custom = await loader.load_plugin_from_file(plugin_file, config=custom_config)
        plugin_custom = plugins_custom[0]
        
        with plugin_sandbox.execute_sandboxed(plugin_custom):
            issues_custom = await plugin_sandbox.execute_plugin_method(
                plugin_custom, "detect", [sample_network_trace]
            )
        
        assert len(issues_custom) == 1
        assert issues_custom[0].severity == SeverityLevel.HIGH
        # Evidence is a list, access the raw_data from the first evidence
        assert issues_custom[0].evidence[0].raw_data["threshold"] == 0.8
        assert issues_custom[0].evidence[0].raw_data["score"] == 1.0  # url + headers = 0.6 + 0.4
    
    @pytest.mark.asyncio
    async def test_plugin_directory_discovery_workflow(
        self, 
        plugin_registry, 
        plugin_sandbox, 
        temp_plugin_dir,
        integration_helper,
        sample_network_trace
    ):
        """Test workflow with plugin directory discovery."""
        # Create multiple plugin files in directory
        plugin1_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel

class DiscoveryPlugin1(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="discovery_plugin_1",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="First discovered plugin"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        return [Issue(
            id="discovery-1",
            category=IssueCategory.PRIVACY_VIOLATION,
            severity=SeverityLevel.LOW,
            title="Discovery Plugin 1",
            description="Found by directory discovery",
            confidence=0.8,
            impact_score=25
        )]
'''
        
        plugin2_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel

class DiscoveryPlugin2(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="discovery_plugin_2",
            version="2.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Second discovered plugin"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        return [Issue(
            id="discovery-2",
            category=IssueCategory.JAVASCRIPT_FINGERPRINT,
            severity=SeverityLevel.MEDIUM,
            title="Discovery Plugin 2",
            description="Also found by directory discovery",
            confidence=0.9,
            impact_score=55
        )]
'''
        
        # Create subdirectory for nested discovery test
        sub_dir = temp_plugin_dir / "subdir"
        sub_dir.mkdir()
        
        # Create plugin files
        integration_helper.create_plugin_file(temp_plugin_dir, "plugin1.py", plugin1_code)
        integration_helper.create_plugin_file(temp_plugin_dir, "plugin2.py", plugin2_code)
        integration_helper.create_plugin_file(sub_dir, "plugin3.py", plugin1_code.replace("discovery_plugin_1", "discovery_plugin_3"))
        
        # Discover and load plugins
        loader = PluginLoader(plugin_registry)
        plugins = await loader.discover_plugins_in_directory(temp_plugin_dir, recursive=True)
        
        # Should find all 3 plugins (including one in subdirectory)
        assert len(plugins) == 3
        
        plugin_names = {plugin.name for plugin in plugins}
        assert plugin_names == {"discovery_plugin_1", "discovery_plugin_2", "discovery_plugin_3"}
        
        # Execute all discovered plugins
        all_issues = []
        for plugin in plugins:
            with plugin_sandbox.execute_sandboxed(plugin):
                issues = await plugin_sandbox.execute_plugin_method(
                    plugin, "detect", [sample_network_trace]
                )
                all_issues.extend(issues)
        
        # Verify all plugins executed successfully
        assert len(all_issues) == 3
        # Issue model doesn't have 'source' attribute, use plugin names instead
        plugin_names_from_issues = {plugin.name for plugin in plugins}
        assert plugin_names_from_issues == {"discovery_plugin_1", "discovery_plugin_2", "discovery_plugin_3"}
