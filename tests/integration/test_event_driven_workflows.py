"""
Integration tests for event-driven workflows.

Tests event emission → subscription → cross-component actions.
"""

import pytest
import asyncio
from typing import List, Dict, Any
from unittest.mock import Mock, AsyncMock, patch

from src.netstealth_analyzer.core.events import EventBus, AnalysisEvent
from src.netstealth_analyzer.plugins.loader import PluginLoader
from src.netstealth_analyzer.plugins.sandbox import PluginSandbox
from src.netstealth_analyzer.plugins.registry import PluginRegistry
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel
from src.netstealth_analyzer.models.network import NetworkTrace, NetworkHop
from src.netstealth_analyzer.models.results import AnalysisResult, AnalysisSummary, ExecutionContext
from src.netstealth_analyzer.config import ConfigurationManager


class TestEventDrivenWorkflows:
    """Test event-driven workflows and cross-component communication."""
    
    @pytest.mark.asyncio
    async def test_plugin_event_chain_workflow(
        self,
        event_bus,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper,
        sample_network_trace
    ):
        """Test event chain: Plugin A emits → Plugin B listens → Plugin C processes."""
        # Plugin A: Event emitter
        emitter_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.core.events import AnalysisEvent
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence

class EventEmitterPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="event_emitter",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin that emits events"
        )
        self.event_bus = None
    
    @property
    def metadata(self):
        return self._metadata
    
    def set_event_bus(self, event_bus):
        self.event_bus = event_bus
    
    async def detect(self, traces):
        issues = []
        for trace in traces:
            # Create issue
            issue = Issue(
                id=f"emitter-{trace.trace_id}",
                category=IssueCategory.NETWORK_ANOMALY,
                severity=SeverityLevel.MEDIUM,
                title="Event Chain Issue",
                description="Issue detected by emitter plugin",
                confidence=0.8,
                impact_score=60,
                evidence=[
                    IssueEvidence(
                        type="emitter_detection",
                        description="Event emitter found anomaly",
                        raw_data={"trace_id": trace.trace_id},
                        confidence=0.8
                    )
                ]
            )
            issues.append(issue)
            
            # Emit event for issue found
            if self.event_bus:
                await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {
                    "plugin_name": self.name,
                    "issue_id": issue.id,
                "severity": issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity),
                    "trace_id": trace.trace_id
                })
                
                # Emit custom analysis event
                await self.event_bus.emit(AnalysisEvent.ANALYSIS_STARTED, {
                    "plugin_name": self.name,
                    "trace_count": len(traces),
                    "phase": "detection"
                })
        
        return issues
'''
        
        # Plugin B: Event listener that processes events
        listener_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.core.events import AnalysisEvent
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence

class EventListenerPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="event_listener",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin that listens to events"
        )
        self.event_bus = None
        self.received_events = []
        self.enhanced_issues = []
    
    @property
    def metadata(self):
        return self._metadata
    
    def set_event_bus(self, event_bus):
        self.event_bus = event_bus
        # Subscribe to events
        if event_bus:
            event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, self.on_issue_found)
            event_bus.subscribe(AnalysisEvent.ANALYSIS_STARTED, self.on_analysis_started)
    
    async def on_issue_found(self, event, event_data):
        """Handle issue found event."""
        self.received_events.append(("ISSUE_FOUND", event_data))
        
        # Create enhanced issue based on event
        enhanced_issue = Issue(
            id=f"enhanced-{event_data.get('issue_id', 'unknown')}",
            category=IssueCategory.PRIVACY_VIOLATION,
            severity=SeverityLevel.HIGH,  # Escalate severity
            title="Enhanced Event-Driven Detection",
            description=f"Enhanced issue based on event from {event_data.get('plugin_name')}",
            confidence=0.9,
            impact_score=80,
            evidence=[
                IssueEvidence(
                    type="event_enhancement",
                    description="Issue enhanced based on event data",
                    raw_data=event_data,
                    confidence=0.9
                )
            ]
        )
        self.enhanced_issues.append(enhanced_issue)
    
    async def on_analysis_started(self, event, event_data):
        """Handle analysis started event."""
        self.received_events.append(("ANALYSIS_STARTED", event_data))
    
    async def detect(self, traces):
        # Return any enhanced issues created from events
        return self.enhanced_issues.copy()
    
    def get_received_events(self):
        return self.received_events.copy()
'''
        
        # Plugin C: Result processor that emits completion events
        processor_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.core.events import AnalysisEvent

class ResultProcessorPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="result_processor",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin that processes results and emits completion events"
        )
        self.event_bus = None
        self.processed_count = 0
    
    @property
    def metadata(self):
        return self._metadata
    
    def set_event_bus(self, event_bus):
        self.event_bus = event_bus
    
    async def detect(self, traces):
        # Process traces and emit completion event
        self.processed_count = len(traces)
        
        if self.event_bus:
            await self.event_bus.emit(AnalysisEvent.ANALYSIS_COMPLETED, {
                "plugin_name": self.name,
                "processed_traces": self.processed_count,
                "timestamp": "2024-01-01T12:00:00Z"
            })
        
        return []  # No issues, just processing
    
    def get_processed_count(self):
        return self.processed_count
'''
        
        # Create plugin files
        emitter_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "emitter_plugin.py", emitter_code
        )
        listener_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "listener_plugin.py", listener_code
        )
        processor_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "processor_plugin.py", processor_code
        )
        
        # Load all plugins
        loader = PluginLoader(plugin_registry)
        emitter_plugins = await loader.load_plugin_from_file(emitter_file)
        listener_plugins = await loader.load_plugin_from_file(listener_file)
        processor_plugins = await loader.load_plugin_from_file(processor_file)
        
        emitter = emitter_plugins[0]
        listener = listener_plugins[0]
        processor = processor_plugins[0]
        
        # Set up event bus for all plugins
        with plugin_sandbox.execute_sandboxed(emitter):
            await plugin_sandbox.execute_plugin_method(emitter, "set_event_bus", event_bus)
        
        with plugin_sandbox.execute_sandboxed(listener):
            await plugin_sandbox.execute_plugin_method(listener, "set_event_bus", event_bus)
        
        with plugin_sandbox.execute_sandboxed(processor):
            await plugin_sandbox.execute_plugin_method(processor, "set_event_bus", event_bus)
        
        # Execute workflow: Emitter → Listener → Processor
        traces = [sample_network_trace]
        
        # Step 1: Emitter detects and emits events
        with plugin_sandbox.execute_sandboxed(emitter):
            emitter_issues = await plugin_sandbox.execute_plugin_method(
                emitter, "detect", traces
            )
        
        # Wait for async event processing
        await asyncio.sleep(0.1)
        
        # Step 2: Listener processes events and creates enhanced issues
        with plugin_sandbox.execute_sandboxed(listener):
            listener_issues = await plugin_sandbox.execute_plugin_method(
                listener, "detect", traces
            )
            received_events = await plugin_sandbox.execute_plugin_method(
                listener, "get_received_events"
            )
        
        # Step 3: Processor emits completion events
        with plugin_sandbox.execute_sandboxed(processor):
            processor_issues = await plugin_sandbox.execute_plugin_method(
                processor, "detect", traces
            )
        
        await asyncio.sleep(0.1)  # Wait for completion events
        
        # Verify workflow results
        assert len(emitter_issues) == 1
        assert emitter_issues[0].title == "Event Chain Issue"
        
        assert len(listener_issues) == 1
        assert listener_issues[0].title == "Enhanced Event-Driven Detection"
        assert listener_issues[0].severity == SeverityLevel.HIGH  # Escalated
        
        assert len(processor_issues) == 0  # No issues, just processing
        
        # Verify event chain
        assert len(received_events) == 2
        event_types = [event[0] for event in received_events]
        assert "ISSUE_FOUND" in event_types
        assert "ANALYSIS_STARTED" in event_types
        
        # Verify event data
        issue_event = next(e for e in received_events if e[0] == "ISSUE_FOUND")
        assert issue_event[1]["plugin_name"] == "event_emitter"
        assert issue_event[1]["severity"] == "medium"
    
    @pytest.mark.asyncio
    async def test_configuration_change_events(
        self,
        event_bus,
        config_manager
    ):
        """Test configuration change events and reactions."""
        config_events = []
        
        async def config_change_listener(event, event_data):
            config_events.append(event_data)
        
        # Subscribe to configuration events
        subscription = event_bus.subscribe(AnalysisEvent.CONFIGURATION_CHANGED, config_change_listener)
        
        # Simulate configuration changes
        await event_bus.emit(AnalysisEvent.CONFIGURATION_CHANGED, {
            "component": "logging",
            "field": "level",
            "old_value": "INFO",
            "new_value": "DEBUG",
            "timestamp": "2024-01-01T12:00:00Z"
        })
        
        await event_bus.emit(AnalysisEvent.CONFIGURATION_CHANGED, {
            "component": "plugins",
            "field": "enable_plugins",
            "old_value": True,
            "new_value": False,
            "timestamp": "2024-01-01T12:00:01Z"
        })
        
        # Wait for event processing
        await asyncio.sleep(0.1)
        
        # Verify events received
        assert len(config_events) == 2
        assert config_events[0]["component"] == "logging"
        assert config_events[0]["new_value"] == "DEBUG"
        assert config_events[1]["component"] == "plugins"
        assert config_events[1]["new_value"] is False
    
    @pytest.mark.asyncio
    async def test_error_event_propagation(
        self,
        event_bus,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper,
        sample_network_trace
    ):
        """Test error event propagation and handling across components."""
        # Plugin that can cause errors and emit error events
        error_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.core.events import AnalysisEvent

class ErrorPronePlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="error_prone_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin that can cause errors"
        )
        self.event_bus = None
    
    @property
    def metadata(self):
        return self._metadata
    
    def set_event_bus(self, event_bus):
        self.event_bus = event_bus
    
    async def detect_with_error(self, traces):
        """Method that intentionally causes an error and emits error event."""
        try:
            # Simulate error condition
            if traces and "error" not in traces[0].trace_id:
                raise ValueError("Simulated plugin error for testing")
        except Exception as e:
            # Emit error event
            if self.event_bus:
                await self.event_bus.emit(AnalysisEvent.ERROR_OCCURRED, {
                    "plugin_name": self.name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "trace_id": traces[0].trace_id if traces else None
                })
            raise  # Re-raise the error
    
    async def detect_successful(self, traces):
        """Method that succeeds and emits success event."""
        if self.event_bus:
            await self.event_bus.emit(AnalysisEvent.PLUGIN_EXECUTED, {
                "plugin_name": self.name,
                "status": "success",
                "traces_processed": len(traces)
            })
        return []
'''
        
        # Error handler plugin that listens for error events
        error_handler_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.core.events import AnalysisEvent

class ErrorHandlerPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="error_handler_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin that handles error events"
        )
        self.event_bus = None
        self.error_events = []
        self.plugin_events = []
    
    @property
    def metadata(self):
        return self._metadata
    
    def set_event_bus(self, event_bus):
        self.event_bus = event_bus
        if event_bus:
            event_bus.subscribe(AnalysisEvent.ERROR_OCCURRED, self.on_error_occurred)
            event_bus.subscribe(AnalysisEvent.PLUGIN_EXECUTED, self.on_plugin_executed)
    
    async def on_error_occurred(self, event, event_data):
        """Handle error events."""
        self.error_events.append(event_data)
    
    async def on_plugin_executed(self, event, event_data):
        """Handle plugin execution events."""
        self.plugin_events.append(event_data)
    
    async def detect(self, traces):
        return []  # No detection, just event handling
    
    def get_error_events(self):
        return self.error_events.copy()
    
    def get_plugin_events(self):
        return self.plugin_events.copy()
'''
        
        # Create plugins
        error_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "error_plugin.py", error_plugin_code
        )
        handler_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "handler_plugin.py", error_handler_code
        )
        
        # Load plugins
        loader = PluginLoader(plugin_registry)
        error_plugins = await loader.load_plugin_from_file(error_file)
        handler_plugins = await loader.load_plugin_from_file(handler_file)
        
        error_plugin = error_plugins[0]
        handler_plugin = handler_plugins[0]
        
        # Set up event bus
        with plugin_sandbox.execute_sandboxed(error_plugin):
            await plugin_sandbox.execute_plugin_method(error_plugin, "set_event_bus", event_bus)
        
        with plugin_sandbox.execute_sandboxed(handler_plugin):
            await plugin_sandbox.execute_plugin_method(handler_plugin, "set_event_bus", event_bus)
        
        # Test error event workflow
        traces = [sample_network_trace]
        
        # Test successful execution first
        with plugin_sandbox.execute_sandboxed(error_plugin):
            await plugin_sandbox.execute_plugin_method(error_plugin, "detect_successful", traces)
        
        await asyncio.sleep(0.1)
        
        # Check handler received success event
        with plugin_sandbox.execute_sandboxed(handler_plugin):
            plugin_events = await plugin_sandbox.execute_plugin_method(
                handler_plugin, "get_plugin_events"
            )
        
        assert len(plugin_events) == 1
        assert plugin_events[0]["status"] == "success"
        assert plugin_events[0]["plugin_name"] == "error_prone_plugin"
        
        # Test error workflow
        with plugin_sandbox.execute_sandboxed(error_plugin):
            try:
                await plugin_sandbox.execute_plugin_method(error_plugin, "detect_with_error", traces)
                assert False, "Should have raised an error"
            except Exception as e:
                assert "execution failed" in str(e).lower()
        
        await asyncio.sleep(0.1)
        
        # Check handler received error event
        with plugin_sandbox.execute_sandboxed(handler_plugin):
            error_events = await plugin_sandbox.execute_plugin_method(
                handler_plugin, "get_error_events"
            )
        
        assert len(error_events) == 1
        assert error_events[0]["plugin_name"] == "error_prone_plugin"
        assert error_events[0]["error_type"] == "ValueError"
        assert "Simulated plugin error" in error_events[0]["error_message"]
    
    @pytest.mark.asyncio
    async def test_multi_component_event_workflow(
        self,
        event_bus,
        plugin_registry,
        plugin_sandbox,
        config_manager,
        temp_plugin_dir,
        integration_helper,
        sample_network_trace
    ):
        """Test complex workflow involving multiple components and event types."""
        # Create workflow coordinator plugin
        coordinator_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.core.events import AnalysisEvent
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence

class WorkflowCoordinator(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="workflow_coordinator",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Coordinates multi-component workflow"
        )
        self.event_bus = None
        self.workflow_state = {
            "phase": "initialized",
            "events_received": [],
            "issues_created": []
        }
    
    @property
    def metadata(self):
        return self._metadata
    
    def set_event_bus(self, event_bus):
        self.event_bus = event_bus
        if event_bus:
            event_bus.subscribe(AnalysisEvent.ANALYSIS_STARTED, self.on_analysis_started)
            event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, self.on_issue_found)
            event_bus.subscribe(AnalysisEvent.CONFIGURATION_CHANGED, self.on_config_changed)
    
    async def on_analysis_started(self, event, event_data):
        """Handle analysis started event."""
        self.workflow_state["phase"] = "analysis_running"
        self.workflow_state["events_received"].append(("ANALYSIS_STARTED", event_data))
        
        # Emit workflow progress event
        if self.event_bus:
            await self.event_bus.emit(AnalysisEvent.PLUGIN_EXECUTED, {
                "plugin_name": self.name,
                "phase": "coordination_started",
                "state": self.workflow_state["phase"]
            })
    
    async def on_issue_found(self, event, event_data):
        """Handle issue found event."""
        self.workflow_state["events_received"].append(("ISSUE_FOUND", event_data))
        
        # Create coordinated issue
        issue = Issue(
            id=f"coordinated-{len(self.workflow_state['issues_created'])}",
            category=IssueCategory.CONFIGURATION,
            severity=SeverityLevel.LOW,
            title="Workflow Coordination Issue",
            description=f"Coordinated response to issue from {event_data.get('plugin_name')}",
            confidence=0.7,
            impact_score=40,
            evidence=[
                IssueEvidence(
                    type="workflow_coordination",
                    description="Issue created by workflow coordinator",
                    raw_data=event_data,
                    confidence=0.7
                )
            ]
        )
        self.workflow_state["issues_created"].append(issue)
    
    async def on_config_changed(self, event, event_data):
        """Handle configuration change event."""
        self.workflow_state["events_received"].append(("CONFIG_CHANGED", event_data))
        
        if event_data.get("component") == "plugins":
            self.workflow_state["phase"] = "plugin_config_changed"
    
    async def detect(self, traces):
        # Start workflow
        if self.event_bus:
            await self.event_bus.emit(AnalysisEvent.ANALYSIS_STARTED, {
                "coordinator": self.name,
                "trace_count": len(traces),
                "workflow_id": "multi-component-test"
            })
        
        return self.workflow_state["issues_created"].copy()
    
    def get_workflow_state(self):
        return self.workflow_state.copy()
'''
        
        # Create coordinator plugin
        coord_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "coordinator.py", coordinator_code
        )
        
        loader = PluginLoader(plugin_registry)
        coord_plugins = await loader.load_plugin_from_file(coord_file)
        coordinator = coord_plugins[0]
        
        # Set up coordinator
        with plugin_sandbox.execute_sandboxed(coordinator):
            await plugin_sandbox.execute_plugin_method(coordinator, "set_event_bus", event_bus)
        
        # Simulate complex workflow
        traces = [sample_network_trace]
        
        # Step 1: Start workflow
        with plugin_sandbox.execute_sandboxed(coordinator):
            coord_issues = await plugin_sandbox.execute_plugin_method(coordinator, "detect", traces)
        
        await asyncio.sleep(0.1)
        
        # Step 2: Simulate external events
        await event_bus.emit(AnalysisEvent.ISSUE_FOUND, {
            "plugin_name": "external_detector",
            "issue_id": "ext-001",
            "severity": "high"
        })
        
        await event_bus.emit(AnalysisEvent.CONFIGURATION_CHANGED, {
            "component": "plugins",
            "field": "enable_hot_reload",
            "old_value": False,
            "new_value": True
        })
        
        await asyncio.sleep(0.1)
        
        # Step 3: Check final workflow state
        with plugin_sandbox.execute_sandboxed(coordinator):
            final_state = await plugin_sandbox.execute_plugin_method(
                coordinator, "get_workflow_state"
            )
            final_issues = await plugin_sandbox.execute_plugin_method(coordinator, "detect", traces)
        
        # Verify complex workflow results
        assert final_state["phase"] == "plugin_config_changed"
        assert len(final_state["events_received"]) >= 3  # Started, Issue found, Config changed
        
        event_types = [event[0] for event in final_state["events_received"]]
        assert "ANALYSIS_STARTED" in event_types
        assert "ISSUE_FOUND" in event_types
        assert "CONFIG_CHANGED" in event_types
        
        # Verify coordinated issue was created
        assert len(final_state["issues_created"]) == 1
        coordinated_issue = final_state["issues_created"][0]
        assert coordinated_issue.title == "Workflow Coordination Issue"
        assert "external_detector" in coordinated_issue.description
    
    @pytest.mark.asyncio
    async def test_event_bus_performance_under_load(self, event_bus):
        """Test event bus performance with high event volume."""
        import time
        
        events_received = []
        
        async def high_volume_listener(event, event_data):
            events_received.append(event_data)
        
        # Subscribe to multiple event types
        subscriptions = [
            event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, high_volume_listener),
            event_bus.subscribe(AnalysisEvent.ANALYSIS_STARTED, high_volume_listener),
            event_bus.subscribe(AnalysisEvent.PLUGIN_EXECUTED, high_volume_listener)
        ]
        
        # Emit high volume of events
        start_time = time.time()
        event_count = 100
        
        for i in range(event_count):
            await event_bus.emit(AnalysisEvent.ISSUE_FOUND, {
                "issue_id": f"perf-test-{i}",
                "plugin_name": f"plugin-{i % 10}",
                "severity": "medium"
            })
            
            if i % 10 == 0:
                await event_bus.emit(AnalysisEvent.ANALYSIS_STARTED, {
                    "batch": i // 10,
                    "plugin_name": f"batch-plugin-{i}"
                })
        
        # Wait for all events to be processed
        await asyncio.sleep(0.2)
        end_time = time.time()
        
        # Verify performance
        processing_time = end_time - start_time
        events_per_second = len(events_received) / processing_time
        
        # Should have received all events
        expected_events = event_count + (event_count // 10)  # Issues + analysis started events
        assert len(events_received) == expected_events
        
        # Performance should be reasonable (>500 events/second)
        assert events_per_second > 500, f"Event processing too slow: {events_per_second:.2f} events/sec"
        
        # Verify event data integrity
        issue_events = [e for e in events_received if "issue_id" in e]
        assert len(issue_events) == event_count
        
        analysis_events = [e for e in events_received if "batch" in e]
        assert len(analysis_events) == event_count // 10
