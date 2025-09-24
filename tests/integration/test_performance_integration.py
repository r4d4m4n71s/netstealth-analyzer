"""
Integration tests for performance across components.

Tests multi-component performance under load and resource usage.
"""

import pytest
import asyncio
import time
import gc
from typing import List
from unittest.mock import Mock, patch

# resource module is not available on Windows
try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False

from src.netstealth_analyzer.plugins.loader import PluginLoader
from src.netstealth_analyzer.plugins.sandbox import PluginSandbox
from src.netstealth_analyzer.plugins.registry import PluginRegistry
from src.netstealth_analyzer.models.network import NetworkTrace, NetworkHop, HttpRequest, HttpResponse
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel
from src.netstealth_analyzer.models.results import AnalysisResult, AnalysisSummary, ExecutionContext
from src.netstealth_analyzer.core.events import EventBus, AnalysisEvent


class TestPerformanceIntegration:
    """Test system performance under various load conditions."""
    
    @pytest.fixture
    def large_trace_dataset(self):
        """Generate large dataset of network traces for performance testing."""
        traces = []
        for i in range(100):  # 100 traces
            trace = NetworkTrace(
                trace_id=f"perf-trace-{i:03d}",
                session_id=f"perf-session-{i // 10}",
                hops=[
                    NetworkHop(
                        hop_number=j+1,
                        hop_id=f"hop-{i}-{j}",
                        actor="client",
                        actor_name=f"Test Client {i}-{j}",
                        incoming_ip="127.0.0.1",
                        outgoing_ip=f"192.168.1.{(i * 3 + j) % 255}",
                        timestamp=1704110400.0 + i * 0.1 + j * 0.01,
                        response_time_ms=50.0 + (i * j) % 200
                    )
                    for j in range(3)  # 3 hops per trace
                ]
            )
            traces.append(trace)
        return traces
    
    @pytest.mark.asyncio
    async def test_plugin_execution_performance(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper,
        large_trace_dataset
    ):
        """Test plugin execution performance with large datasets."""
        # Create performance test plugin
        perf_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence

class PerformanceTestPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="performance_test_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin for performance testing"
        )
        self.processed_count = 0
        self.issues_created = 0
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Process traces with some computational work."""
        issues = []
        self.processed_count = len(traces)
        
        for trace in traces:
            # Simulate some processing work
            total_latency = sum(hop.response_time_ms or 0 for hop in trace.hops)
            hop_count = len(trace.hops)
            
            # Create issues based on performance criteria
            if total_latency > 200:  # High latency
                issue = Issue(
                    id=f"perf-latency-{trace.trace_id}",
                    category=IssueCategory.NETWORK_ANOMALY,
                    severity=SeverityLevel.MEDIUM,
                    title="High Latency Detected",
                    description=f"Total latency {total_latency:.1f}ms exceeds threshold",
                    confidence=0.8,
                    impact_score=60,
                    evidence=[
                        IssueEvidence(
                            type="latency_analysis",
                            description="High network latency detected",
                            raw_data={"total_latency": total_latency, "hop_count": hop_count},
                            confidence=0.8
                        )
                    ]
                )
                issues.append(issue)
                self.issues_created += 1
            
            # Simulate more complex analysis using actual NetworkHop fields
            for hop in trace.hops:
                # Check for suspicious IP patterns or high-risk hops
                if hop.risk_level.numeric_value > 2:  # Medium or higher risk
                    issue = Issue(
                        id=f"perf-risk-{trace.trace_id}-{hop.hop_number}",
                        category=IssueCategory.NETWORK_ANOMALY,
                        severity=SeverityLevel.LOW,
                        title=f"High Risk Hop Detected",
                        description=f"Hop {hop.hop_number} shows elevated risk",
                        confidence=0.9,
                        impact_score=30,
                        evidence=[
                            IssueEvidence(
                                type="risk_analysis",
                                description="High risk hop detected",
                                raw_data={"risk_level": hop.risk_level.value, "hop_id": hop.hop_id},
                                confidence=0.9
                            )
                        ]
                    )
                    issues.append(issue)
                    self.issues_created += 1
        
        return issues
    
    def get_stats(self):
        return {
            "processed_count": self.processed_count,
            "issues_created": self.issues_created
        }
'''
        
        # Create plugin
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "performance_plugin.py", perf_plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        perf_plugin = plugins[0]
        
        # Measure execution time and memory usage
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        start_time = time.time()
        
        # Execute plugin with large dataset
        with plugin_sandbox.execute_sandboxed(perf_plugin):
            issues = await plugin_sandbox.execute_plugin_method(
                perf_plugin, "detect", large_trace_dataset
            )
            stats = await plugin_sandbox.execute_plugin_method(
                perf_plugin, "get_stats"
            )
        
        end_time = time.time()
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Verify performance metrics
        execution_time = end_time - start_time
        memory_usage = final_memory - initial_memory
        traces_per_second = len(large_trace_dataset) / execution_time
        
        # Performance assertions
        assert execution_time < 5.0, f"Execution too slow: {execution_time:.2f}s"
        assert memory_usage < 100, f"Memory usage too high: {memory_usage:.1f}MB"
        assert traces_per_second > 20, f"Processing too slow: {traces_per_second:.1f} traces/sec"
        
        # Verify functional correctness
        assert stats["processed_count"] == len(large_trace_dataset)
        assert len(issues) == stats["issues_created"]
        
        # Verify some issues were created (based on our test data)
        high_latency_issues = [i for i in issues if "High Latency" in i.title]
        risk_issues = [i for i in issues if "High Risk Hop" in i.title]
        
        assert len(high_latency_issues) > 0, "Should have detected some high latency issues"
        # Risk issues depend on NetworkHop risk levels, which default to SAFE, so may not be detected
        # assert len(risk_issues) >= 0, "May have detected some high risk hop issues"
    
    @pytest.mark.asyncio
    async def test_concurrent_plugin_execution(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper,
        large_trace_dataset
    ):
        """Test concurrent execution of multiple plugins."""
        # Create multiple concurrent plugins
        plugins_data = []
        for i in range(5):  # 5 concurrent plugins
            plugin_code = f'''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence
import asyncio

class ConcurrentPlugin{i}(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="concurrent_plugin_{i}",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Concurrent plugin {i}"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Detect issues with some async work."""
        issues = []
        
        # Simulate some async processing work
        await asyncio.sleep(0.01)
        
        for trace in traces[{i}::5]:  # Process every 5th trace starting from {i}
            if len(trace.hops) > 2:
                issue = Issue(
                    id=f"concurrent-{i}-{{trace.trace_id}}",
                    category=IssueCategory.PRIVACY_VIOLATION,
                    severity=SeverityLevel.LOW,
                    title=f"Concurrent Detection {i}",
                    description=f"Issue detected by plugin {i}",
                    confidence=0.7,
                impact_score=30 + {i} * 5,
                    evidence=[
                        IssueEvidence(
                            type="concurrent_test",
                            description=f"Concurrent detection by plugin {i}",
                            raw_data={{"plugin_id": {i}, "trace_id": trace.trace_id}},
                            confidence=0.7
                        )
                    ]
                )
                issues.append(issue)
        
        return issues
'''
            
            plugin_file = integration_helper.create_plugin_file(
                temp_plugin_dir, f"concurrent_plugin_{i}.py", plugin_code
            )
            
            loader = PluginLoader(plugin_registry)
            plugins = await loader.load_plugin_from_file(plugin_file)
            plugins_data.append(plugins[0])
        
        # Execute all plugins concurrently
        start_time = time.time()
        
        async def execute_plugin(plugin):
            with plugin_sandbox.execute_sandboxed(plugin):
                return await plugin_sandbox.execute_plugin_method(
                    plugin, "detect", large_trace_dataset
                )
        
        # Run all plugins concurrently
        results = await asyncio.gather(*[execute_plugin(plugin) for plugin in plugins_data])
        
        end_time = time.time()
        concurrent_time = end_time - start_time
        
        # Compare with sequential execution time
        start_seq = time.time()
        sequential_results = []
        for plugin in plugins_data:
            with plugin_sandbox.execute_sandboxed(plugin):
                result = await plugin_sandbox.execute_plugin_method(
                    plugin, "detect", large_trace_dataset
                )
                sequential_results.append(result)
        end_seq = time.time()
        sequential_time = end_seq - start_seq
        
        # Verify concurrent execution is faster
        assert concurrent_time < sequential_time * 0.8, f"Concurrent execution not significantly faster: {concurrent_time:.2f}s vs {sequential_time:.2f}s"
        
        # Verify all plugins executed successfully
        assert len(results) == 5
        for i, result in enumerate(results):
            assert len(result) > 0, f"Plugin {i} should have detected some issues"
            # Each plugin processes every 5th trace, so should have ~20 issues
            assert 15 < len(result) < 25, f"Plugin {i} detected unexpected number of issues: {len(result)}"
    
    @pytest.mark.asyncio
    async def test_event_system_performance(self, event_bus):
        """Test event system performance with high throughput."""
        events_received = []
        processing_times = []
        
        async def performance_listener(event, event_data):
            start_time = time.time()
            # Simulate some processing work
            await asyncio.sleep(0.001)  # 1ms processing time
            end_time = time.time()
            
            events_received.append(event_data)
            processing_times.append(end_time - start_time)
        
        # Subscribe to events
        subscription = event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, performance_listener)
        
        # Emit many events rapidly
        event_count = 1000
        start_time = time.time()
        
        for i in range(event_count):
            await event_bus.emit(AnalysisEvent.ISSUE_FOUND, {
                "issue_id": f"perf-{i:04d}",
                "plugin_name": f"perf-plugin-{i % 10}",
                "severity": "medium",
                "timestamp": time.time()
            })
        
        # Wait for all events to be processed
        await asyncio.sleep(2.0)  # Give enough time for all events to process
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Verify performance
        events_per_second = len(events_received) / total_time
        
        assert len(events_received) == event_count, f"Not all events received: {len(events_received)}/{event_count}"
        assert events_per_second > 200, f"Event processing too slow: {events_per_second:.1f} events/sec"
        
        # Verify processing times are reasonable
        avg_processing_time = sum(processing_times) / len(processing_times)
        max_processing_time = max(processing_times)
        
        assert avg_processing_time < 0.05, f"Average processing time too high: {avg_processing_time:.3f}s"
        assert max_processing_time < 0.05, f"Maximum processing time too high: {max_processing_time:.3f}s"
    
    @pytest.mark.asyncio
    async def test_memory_usage_under_load(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper
    ):
        """Test memory usage patterns under sustained load."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        # Create memory-intensive plugin
        memory_plugin_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence

class MemoryTestPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="memory_test_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin for memory testing"
        )
        self.cache = {}
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Process traces with controlled memory usage."""
        issues = []
        
        for trace in traces:
            # Create some data structures for analysis
            trace_data = {
                "trace_id": trace.trace_id,
                "hop_count": len(trace.hops),
                "total_latency": sum(hop.response_time_ms or 0 for hop in trace.hops),
                "actors": [hop.actor_name for hop in trace.hops],
                "analysis_cache": list(range(1000))  # Create some memory usage
            }
            
            # Cache analysis results (controlled memory growth)
            cache_key = f"analysis_{trace.trace_id}"
            self.cache[cache_key] = trace_data
            
            # Limit cache size to prevent unbounded growth
            if len(self.cache) > 50:
                # Remove oldest entries
                oldest_keys = list(self.cache.keys())[:25]
                for key in oldest_keys:
                    del self.cache[key]
            
            # Create issue if certain conditions are met
            if trace_data["total_latency"] > 150:
                issue = Issue(
                    id=f"mem-test-{trace.trace_id}",
                    category=IssueCategory.NETWORK_ANOMALY,
                    severity=SeverityLevel.LOW,
                    title="Memory Test Detection",
                    description="Issue detected during memory test",
                    confidence=0.8,
                    impact_score=40,
                    evidence=[
                        IssueEvidence(
                            type="memory_test",
                            description="Memory test detection",
                            raw_data=trace_data,
                            confidence=0.8
                        )
                    ]
                )
                issues.append(issue)
        
        return issues
    
    def get_cache_size(self):
        return len(self.cache)
    
    def clear_cache(self):
        self.cache.clear()
'''
        
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "memory_plugin.py", memory_plugin_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        memory_plugin = plugins[0]
        
        # Monitor memory usage over multiple executions
        memory_readings = []
        
        for iteration in range(10):
            # Create traces for this iteration
            traces = []
            for i in range(20):  # 20 traces per iteration
                trace = NetworkTrace(
                    trace_id=f"mem-test-{iteration:02d}-{i:03d}",
                    session_id=f"mem-session-{iteration}",
                    hops=[
                        NetworkHop(
                            hop_number=1,
                            hop_id=f"mem-hop-{iteration}-{i}",
                            actor="client",
                            actor_name=f"Memory Test Client {iteration}-{i}",
                            incoming_ip="127.0.0.1",
                            outgoing_ip=f"10.0.{iteration}.{i}",
                            response_time_ms=100.0 + (iteration * i) % 100
                        )
                    ]
                )
                traces.append(trace)
            
            # Execute plugin and measure memory
            with plugin_sandbox.execute_sandboxed(memory_plugin):
                issues = await plugin_sandbox.execute_plugin_method(
                    memory_plugin, "detect", traces
                )
                cache_size = await plugin_sandbox.execute_plugin_method(
                    memory_plugin, "get_cache_size"
                )
            
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_readings.append(current_memory)
            
            # Verify cache size is controlled
            assert cache_size <= 50, f"Cache size not controlled: {cache_size}"
        
        # Verify memory usage is stable (no significant memory leaks)
        initial_memory = memory_readings[0]
        final_memory = memory_readings[-1]
        memory_growth = final_memory - initial_memory
        
        # Memory should not grow significantly (allow some variance)
        assert memory_growth < 50, f"Potential memory leak detected: {memory_growth:.1f}MB growth"
        
        # Verify plugin still functions correctly
        assert len(issues) > 0, "Plugin should still detect issues in final iteration"
        
        # Test explicit cleanup
        with plugin_sandbox.execute_sandboxed(memory_plugin):
            await plugin_sandbox.execute_plugin_method(memory_plugin, "clear_cache")
            cache_size_after_clear = await plugin_sandbox.execute_plugin_method(
                memory_plugin, "get_cache_size"
            )
        
        assert cache_size_after_clear == 0, "Cache should be empty after clearing"
    
    @pytest.mark.asyncio
    async def test_end_to_end_performance_benchmark(
        self,
        plugin_registry,
        plugin_sandbox,
        temp_plugin_dir,
        integration_helper,
        event_bus
    ):
        """Comprehensive end-to-end performance benchmark."""
        import psutil
        import os
        
        # Create benchmark detector plugin
        benchmark_code = '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence
from src.netstealth_analyzer.core.events import AnalysisEvent

class BenchmarkPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="benchmark_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Comprehensive benchmark plugin"
        )
        self.event_bus = None
    
    @property
    def metadata(self):
        return self._metadata
    
    def set_event_bus(self, event_bus):
        self.event_bus = event_bus
    
    async def detect(self, traces):
        """Comprehensive detection with event emission."""
        issues = []
        
        # Emit start event
        if self.event_bus:
            await self.event_bus.emit(AnalysisEvent.ANALYSIS_STARTED, {
                "plugin_name": self.name,
                "trace_count": len(traces),
                "phase": "comprehensive_analysis"
            })
        
        for trace in traces:
            # Comprehensive analysis simulation
            analysis_score = 0
            findings = []
            
            # Analyze hops using actual NetworkHop fields
            for hop in trace.hops:
                if hop.response_time_ms and hop.response_time_ms > 100:
                    analysis_score += 10
                    findings.append(f"High response time: {hop.response_time_ms}ms")
                
                # Check for high-risk hops
                if hop.risk_level.numeric_value > 1:  # Above SAFE
                    analysis_score += 20
                    findings.append(f"Risk level: {hop.risk_level.value}")
                
                # Check for anomalies
                if hop.anomalies:
                    analysis_score += 30
                    findings.append(f"Anomalies detected: {len(hop.anomalies)}")
            
            # Create issue if analysis score is high enough
            if analysis_score >= 30:
                issue = Issue(
                    id=f"benchmark-{trace.trace_id}",
                    category=IssueCategory.NETWORK_ANOMALY,
                    severity=SeverityLevel.MEDIUM if analysis_score < 50 else SeverityLevel.HIGH,
                    title="Comprehensive Analysis Detection",
                    description=f"Analysis score: {analysis_score}, Findings: {findings}",
                    confidence=min(0.9, analysis_score / 100),
                    impact_score=min(100, analysis_score),
                    evidence=[
                        IssueEvidence(
                            type="comprehensive_analysis",
                            description="Comprehensive benchmark analysis",
                            raw_data={
                                "analysis_score": analysis_score,
                                "findings": findings,
                                "trace_id": trace.trace_id
                            },
                            confidence=min(0.9, analysis_score / 100)
                        )
                    ]
                )
                issues.append(issue)
                
                # Emit issue found event
                if self.event_bus:
                    await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {
                        "plugin_name": self.name,
                        "issue_id": issue.id,
                "severity": issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity),
                        "analysis_score": analysis_score
                    })
        
        # Emit completion event
        if self.event_bus:
            await self.event_bus.emit(AnalysisEvent.ANALYSIS_COMPLETED, {
                "plugin_name": self.name,
                "issues_found": len(issues),
                "traces_processed": len(traces)
            })
        
        return issues
'''
        
        # Create plugin and large dataset
        plugin_file = integration_helper.create_plugin_file(
            temp_plugin_dir, "benchmark_plugin.py", benchmark_code
        )
        
        loader = PluginLoader(plugin_registry)
        plugins = await loader.load_plugin_from_file(plugin_file)
        benchmark_plugin = plugins[0]
        
        # Create comprehensive test dataset
        traces = []
        for i in range(200):  # Larger dataset for benchmarking
            hops = []
            for j in range(2 + i % 3):  # Variable number of hops
                hostname = f"host{i}-{j}.example.com"
                if i % 10 == 7:  # Some tracking domains
                    hostname = f"tracking{i}.ads.com"
                
                hop = NetworkHop(
                    hop_number=j+1,
                    hop_id=f"benchmark-hop-{i}-{j}",
                    actor="benchmark_client",
                    actor_name=f"Benchmark Client {i}-{j}",
                    incoming_ip="127.0.0.1",
                    outgoing_ip=f"192.168.{(i // 50) + 1}.{i % 50 + 1}",
                    response_time_ms=30.0 + (i * j) % 150,  # Variable response time
                    anomalies=["tracking_domain"] if "tracking" in hostname else []
                )
                hops.append(hop)
            
            trace = NetworkTrace(
                trace_id=f"benchmark-trace-{i:03d}",
                session_id=f"benchmark-session-{i // 20}",
                hops=hops
            )
            traces.append(trace)
        
        # Set up event monitoring
        events_received = []
        async def event_monitor(event, event_data):
            events_received.append((event.value, event_data))
        
        event_bus.subscribe(AnalysisEvent.ANALYSIS_STARTED, event_monitor)
        event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, event_monitor)
        event_bus.subscribe(AnalysisEvent.ANALYSIS_COMPLETED, event_monitor)
        
        # Run comprehensive benchmark
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        start_time = time.time()
        
        with plugin_sandbox.execute_sandboxed(benchmark_plugin):
            await plugin_sandbox.execute_plugin_method(benchmark_plugin, "set_event_bus", event_bus)
            issues = await plugin_sandbox.execute_plugin_method(benchmark_plugin, "detect", traces)
        
        end_time = time.time()
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Wait for events to be processed
        await asyncio.sleep(0.2)
        
        # Calculate performance metrics
        execution_time = end_time - start_time
        memory_usage = final_memory - initial_memory
        traces_per_second = len(traces) / execution_time
        issues_per_second = len(issues) / execution_time
        
        # Performance benchmarks
        benchmark_results = {
            "execution_time": execution_time,
            "memory_usage_mb": memory_usage,
            "traces_processed": len(traces),
            "traces_per_second": traces_per_second,
            "issues_detected": len(issues),
            "issues_per_second": issues_per_second,
            "events_emitted": len(events_received)
        }
        
        # Verify performance targets
        assert execution_time < 10.0, f"Benchmark too slow: {execution_time:.2f}s"
        assert memory_usage < 200, f"Memory usage too high: {memory_usage:.1f}MB"
        assert traces_per_second > 20, f"Processing too slow: {traces_per_second:.1f} traces/sec"
        
        # Verify functional correctness
        assert len(issues) > 0, "Should have detected some issues"
        assert len(events_received) >= 2, "Should have emitted start and completion events"
        
        # Verify event system worked
        event_types = [event[0] for event in events_received]
        assert AnalysisEvent.ANALYSIS_STARTED.value in event_types or 1 in event_types
        assert AnalysisEvent.ANALYSIS_COMPLETED.value in event_types or 2 in event_types
        
        if len(issues) > 0:
            assert AnalysisEvent.ISSUE_FOUND.value in event_types or 16 in event_types
        
        # Log benchmark results for reference
        print(f"\n=== Performance Benchmark Results ===")
        print(f"Execution Time: {execution_time:.2f}s")
        print(f"Memory Usage: {memory_usage:.1f}MB")
        print(f"Traces/Second: {traces_per_second:.1f}")
        print(f"Issues/Second: {issues_per_second:.1f}")
        print(f"Events Emitted: {len(events_received)}")
        
        return benchmark_results
