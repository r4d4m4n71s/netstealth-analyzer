"""
Comprehensive tests for NetStealth Analyzer main module.

This test module provides extensive coverage for the main analyzer class,
including initialization, analysis workflows, error handling, and edge cases.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock, call
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List

from netstealth_analyzer.analyzer import NetStealthAnalyzer
from netstealth_analyzer.config import NetStealthConfig
from netstealth_analyzer.core.events import EventBus, AnalysisEvent
from netstealth_analyzer.core.interfaces import ILogParser, IDetector, IReporter, IComponent, ProcessingContext, ProcessingResult
from netstealth_analyzer.models.enums import LogFormat, AnalysisStatus, SeverityLevel
from netstealth_analyzer.models.results import AnalysisResult, ExecutionContext, AnalysisSummary
from netstealth_analyzer.models.issues import Issue
from netstealth_analyzer.models.network import NetworkTrace


class MockPipeline:
    """Mock pipeline for testing."""
    
    def __init__(self, name: str, event_bus: EventBus):
        self.name = name
        self.event_bus = event_bus
        self._initialized = False

    async def initialize(self, config: Dict[str, Any]) -> None:
        """Mock initialization."""
        self._initialized = True

    async def shutdown(self) -> None:
        """Mock shutdown."""
        self._initialized = False

    async def execute(self, input_data: Dict[str, Any], context: ProcessingContext):
        """Mock pipeline execution."""
        # Simulate successful execution
        return ProcessingResult(
            success=True,
            data={
                'issues': [
                    {
                        'id': 'test_issue_1',
                        'title': 'Test Issue',
                        'description': 'Test description',
                        'severity': 'medium',
                        'category': 'security',
                        'detection_vector': 'proxy'
                    }
                ],
                'network_traces': [
                    {
                        'trace_id': 'trace_1',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'source_ip': '192.168.1.1',
                        'destination_ip': '10.0.0.1',
                        'protocol': 'http',
                        'metadata': {}
                    }
                ],
                'functional_indicators': {
                    'proxy_detected': True,
                    'encryption_active': True
                }
            },
            processing_time_ms=1000
        )

    async def execute_streaming(self, input_stream, context: ProcessingContext):
        """Mock streaming execution."""
        async for input_item in input_stream:
            yield {
                'file_processed': input_item.get('file_path'),
                'current': input_item.get('file_index', 0) + 1,
                'total': input_item.get('total_files', 1),
                'message': f"Processing {input_item.get('file_path')}"
            }


@pytest.fixture
def mock_config():
    """Create mock configuration."""
    config = Mock(spec=NetStealthConfig)
    config.target_service = "test_service"
    config.geography = "US"
    config.performance = Mock()
    config.performance.model_dump.return_value = {"max_workers": 4}
    config.model_dump.return_value = {"target_service": "test_service"}
    return config


@pytest.fixture
def mock_event_bus():
    """Create mock event bus."""
    event_bus = Mock(spec=EventBus)
    event_bus.emit = AsyncMock()
    return event_bus


@pytest.fixture
def mock_components():
    """Create mock components (parsers, detectors, reporters, plugins)."""
    # Mock parser
    parser = Mock(spec=ILogParser)
    parser.initialize = AsyncMock()
    parser.shutdown = AsyncMock()
    
    # Mock detector  
    detector = Mock(spec=IDetector)
    detector.initialize = AsyncMock()
    detector.shutdown = AsyncMock()
    
    # Mock reporter
    reporter = Mock(spec=IReporter)
    reporter.initialize = AsyncMock()
    reporter.shutdown = AsyncMock()
    
    # Mock plugin
    plugin = Mock(spec=IComponent)
    plugin.initialize = AsyncMock()
    plugin.shutdown = AsyncMock()
    plugin.metadata = Mock()
    plugin.metadata.name = "test_plugin"
    
    return {
        'parsers': [parser],
        'detectors': [detector], 
        'reporters': [reporter],
        'plugins': [plugin]
    }


@pytest.fixture
def sample_log_files():
    """Create sample log file paths."""
    return [Path("/tmp/test1.log"), Path("/tmp/test2.log")]


@pytest.fixture
def sample_log_formats(sample_log_files):
    """Create sample log format mapping."""
    return {
        sample_log_files[0]: LogFormat.HAR,
        sample_log_files[1]: LogFormat.MITMPROXY
    }


@pytest.fixture
def analyzer(mock_config, mock_event_bus, sample_log_files, sample_log_formats, mock_components):
    """Create NetStealthAnalyzer instance for testing."""
    with patch('netstealth_analyzer.analyzer.PipelineEngine') as mock_pipeline_class:
        mock_pipeline_class.return_value = MockPipeline("test_pipeline", mock_event_bus)
        
        analyzer = NetStealthAnalyzer(
            config=mock_config,
            event_bus=mock_event_bus,
            log_files=sample_log_files,
            log_formats=sample_log_formats,
            parsers=mock_components['parsers'],
            detectors=mock_components['detectors'],
            reporters=mock_components['reporters'],
            plugins=mock_components['plugins']
        )
        
        return analyzer


class TestNetStealthAnalyzerInit:
    """Test analyzer initialization and setup."""

    def test_init_basic(self, analyzer, mock_config, mock_event_bus, sample_log_files):
        """Test basic initialization."""
        assert analyzer.config == mock_config
        assert analyzer._event_bus == mock_event_bus
        assert analyzer._log_files == sample_log_files
        assert not analyzer.is_initialized
        assert analyzer.current_analysis is None

    def test_init_with_progress_callback(self, mock_config, mock_event_bus, sample_log_files, sample_log_formats, mock_components):
        """Test initialization with progress callback."""
        callback = Mock()
        
        with patch('netstealth_analyzer.analyzer.PipelineEngine') as mock_pipeline_class:
            mock_pipeline_class.return_value = MockPipeline("test", mock_event_bus)
            
            analyzer = NetStealthAnalyzer(
                config=mock_config,
                event_bus=mock_event_bus,
                log_files=sample_log_files,
                log_formats=sample_log_formats,
                parsers=mock_components['parsers'],
                detectors=mock_components['detectors'],
                reporters=mock_components['reporters'],
                plugins=mock_components['plugins'],
                progress_callback=callback
            )
            
            assert analyzer._progress_callback == callback

    def test_create_classmethod(self):
        """Test create classmethod returns builder."""
        with patch('netstealth_analyzer.builder.AnalyzerBuilder') as mock_builder:
            result = NetStealthAnalyzer.create()
            mock_builder.assert_called_once()
            assert result == mock_builder.return_value

    def test_properties(self, analyzer, mock_config):
        """Test property accessors."""
        assert analyzer.config == mock_config
        assert not analyzer.is_initialized
        assert analyzer.current_analysis is None


class TestNetStealthAnalyzerLifecycle:
    """Test analyzer lifecycle management."""

    @pytest.mark.asyncio
    async def test_initialize_success(self, analyzer, mock_event_bus, mock_components):
        """Test successful initialization."""
        await analyzer.initialize()
        
        assert analyzer.is_initialized
        
        # Verify components were initialized
        for component in mock_components['parsers']:
            component.initialize.assert_called_once()
        for component in mock_components['detectors']:
            component.initialize.assert_called_once()
        for component in mock_components['reporters']:
            component.initialize.assert_called_once()
        for component in mock_components['plugins']:
            component.initialize.assert_called_once()
        
        # Verify event was emitted
        mock_event_bus.emit.assert_called_with(
            AnalysisEvent.ANALYSIS_STARTED,
            {
                'analyzer_version': '2.0.0',
                'log_files_count': 2,
                'components_count': 4
            }
        )

    @pytest.mark.asyncio
    async def test_initialize_idempotent(self, analyzer):
        """Test that initialize can be called multiple times safely."""
        await analyzer.initialize()
        assert analyzer.is_initialized
        
        # Call again
        await analyzer.initialize()
        assert analyzer.is_initialized

    @pytest.mark.asyncio
    async def test_initialize_component_failure(self, analyzer, mock_components):
        """Test initialization failure when component fails."""
        # Make one component fail
        mock_components['parsers'][0].initialize.side_effect = Exception("Component failed")
        
        with pytest.raises(Exception, match="Component failed"):
            await analyzer.initialize()
        
        assert not analyzer.is_initialized

    @pytest.mark.asyncio
    async def test_shutdown_success(self, analyzer, mock_components):
        """Test successful shutdown."""
        await analyzer.initialize()
        await analyzer.shutdown()
        
        assert not analyzer.is_initialized
        
        # Verify components were shutdown
        for component in mock_components['parsers']:
            component.shutdown.assert_called_once()
        for component in mock_components['detectors']:
            component.shutdown.assert_called_once()
        for component in mock_components['reporters']:
            component.shutdown.assert_called_once()
        for component in mock_components['plugins']:
            component.shutdown.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_without_init(self, analyzer):
        """Test shutdown when not initialized."""
        await analyzer.shutdown()  # Should not raise

    @pytest.mark.asyncio
    async def test_shutdown_component_failure(self, analyzer, mock_components):
        """Test shutdown with component failure."""
        await analyzer.initialize()
        
        # Make shutdown fail
        mock_components['parsers'][0].shutdown.side_effect = Exception("Shutdown failed")
        
        with pytest.raises(Exception, match="Shutdown failed"):
            await analyzer.shutdown()


class TestNetStealthAnalyzerAnalysis:
    """Test main analysis functionality."""

    @pytest.mark.asyncio
    async def test_analyze_no_log_files(self, mock_config, mock_event_bus, mock_components):
        """Test analysis with no log files."""
        with patch('netstealth_analyzer.analyzer.PipelineEngine') as mock_pipeline_class:
            mock_pipeline_class.return_value = MockPipeline("test", mock_event_bus)
            
            analyzer = NetStealthAnalyzer(
                config=mock_config,
                event_bus=mock_event_bus,
                log_files=[],  # No log files
                log_formats={},
                parsers=mock_components['parsers'],
                detectors=mock_components['detectors'],
                reporters=mock_components['reporters'],
                plugins=mock_components['plugins']
            )
            
            with pytest.raises(ValueError, match="No log files configured"):
                await analyzer.analyze()

    @pytest.mark.asyncio
    async def test_analyze_pipeline_failure(self, analyzer, mock_event_bus):
        """Test analysis when pipeline fails."""
        # Mock pipeline to return failure
        with patch.object(analyzer._pipeline, 'execute') as mock_execute:
            mock_execute.return_value = ProcessingResult(
                success=False,
                data=None,
                error=Exception("Pipeline failed")
            )
            
            result = await analyzer.analyze()
            
            assert result.summary.status == AnalysisStatus.FAILED
            assert result.summary.overall_score == 100  # No pipeline data means default score

    @pytest.mark.asyncio
    async def test_stream_analysis_no_files(self, mock_config, mock_event_bus, mock_components):
        """Test streaming analysis with no files."""
        with patch('netstealth_analyzer.analyzer.PipelineEngine') as mock_pipeline_class:
            mock_pipeline_class.return_value = MockPipeline("test", mock_event_bus)
            
            analyzer = NetStealthAnalyzer(
                config=mock_config,
                event_bus=mock_event_bus,
                log_files=[],
                log_formats={},
                parsers=mock_components['parsers'],
                detectors=mock_components['detectors'],
                reporters=mock_components['reporters'],
                plugins=mock_components['plugins']
            )
            
            with pytest.raises(ValueError, match="No log files configured"):
                async for _ in analyzer.stream_analysis():
                    pass

    @pytest.mark.asyncio
    async def test_analyze_single_file(self, analyzer):
        """Test single file analysis."""
        test_file = Path("/tmp/single.log")
        
        with patch('netstealth_analyzer.builder.AnalyzerBuilder') as mock_builder_class:
            mock_builder = Mock()
            mock_temp_analyzer = Mock()
            mock_temp_analyzer.analyze = AsyncMock()
            mock_temp_analyzer.shutdown = AsyncMock()
            mock_result = Mock(spec=AnalysisResult)
            mock_temp_analyzer.analyze.return_value = mock_result
            
            mock_builder.with_log.return_value = mock_builder
            mock_builder.for_service.return_value = mock_builder
            mock_builder.in_geography.return_value = mock_builder
            mock_builder.build.return_value = mock_temp_analyzer
            mock_builder_class.return_value = mock_builder
            
            result = await analyzer.analyze_single_file(test_file, LogFormat.HAR)
            
            assert result == mock_result
            mock_builder.with_log.assert_called_once_with(test_file, LogFormat.HAR)
            mock_builder.for_service.assert_called_once_with("test_service")
            mock_builder.in_geography.assert_called_once_with("US")
            mock_temp_analyzer.analyze.assert_called_once()
            mock_temp_analyzer.shutdown.assert_called_once()


class TestNetStealthAnalyzerResults:
    """Test result processing and retrieval."""

    def test_get_analysis_summary_no_results(self, analyzer):
        """Test getting analysis summary when no results exist."""
        summary = analyzer.get_analysis_summary()
        assert summary is None

    def test_get_issues_by_severity_invalid(self, analyzer):
        """Test getting issues with invalid severity."""
        issues = analyzer.get_issues_by_severity("invalid")
        assert issues == []

    def test_get_issues_by_severity_no_results(self, analyzer):
        """Test getting issues when no analysis has been performed."""
        issues = analyzer.get_issues_by_severity("high")
        assert issues == []

    def test_get_network_traces_no_results(self, analyzer):
        """Test getting network traces when no analysis has been performed."""
        traces = analyzer.get_network_traces()
        assert traces == []


class TestNetStealthAnalyzerHelpers:
    """Test helper and utility methods."""

    def test_calculate_overall_score_no_issues(self, analyzer):
        """Test score calculation with no issues."""
        pipeline_data = {
            'issues': [],
            'functional_indicators': {'proxy_detected': True}
        }
        
        score = analyzer._calculate_overall_score(pipeline_data)
        assert score == 100  # Capped at 100

    def test_calculate_overall_score_with_issues(self, analyzer):
        """Test score calculation with various issue severities."""
        pipeline_data = {
            'issues': [
                {'severity': 'critical'},
                {'severity': 'high'},
                {'severity': 'medium'},
                {'severity': 'low'},
                {'severity': 'info'}
            ],
            'functional_indicators': {}
        }
        
        score = analyzer._calculate_overall_score(pipeline_data)
        # 100 - 20 - 10 - 5 - 2 - 1 = 62
        assert score == 62

    def test_calculate_overall_score_bounds(self, analyzer):
        """Test score calculation respects bounds."""
        # Test minimum bound
        pipeline_data = {
            'issues': [{'severity': 'critical'} for _ in range(10)],  # 200 points deducted
            'functional_indicators': {}
        }
        
        score = analyzer._calculate_overall_score(pipeline_data)
        assert score == 0  # Cannot go below 0

    def test_process_streaming_result_none(self, analyzer):
        """Test processing None streaming result."""
        result = analyzer._process_streaming_result(None)
        assert result is None

    def test_process_streaming_result_valid(self, analyzer):
        """Test processing valid streaming result."""
        input_result = {'test_key': 'test_value'}
        
        result = analyzer._process_streaming_result(input_result)
        
        assert result is not None
        assert result['type'] == 'analysis_update'
        assert result['analyzer_version'] == '2.0.0'
        assert result['test_key'] == 'test_value'
        assert 'timestamp' in result

    @pytest.mark.asyncio
    async def test_create_input_stream(self, analyzer, sample_log_files):
        """Test creating input stream from log files."""
        items = []
        async for item in analyzer._create_input_stream():
            items.append(item)
        
        assert len(items) == len(sample_log_files)
        
        for i, item in enumerate(items):
            assert item['file_path'] == sample_log_files[i]
            assert item['file_index'] == i
            assert item['total_files'] == len(sample_log_files)
            assert 'timestamp' in item

    @pytest.mark.asyncio
    async def test_process_pipeline_results_with_issues(self, analyzer):
        """Test processing pipeline results with issues."""
        result = Mock(spec=AnalysisResult)
        result.add_issue = Mock()
        
        pipeline_data = {
            'issues': [
                {
                    'id': 'test_issue',
                    'title': 'Test Issue',
                    'description': 'Test description',
                    'severity': 'high',
                    'category': 'security',
                    'detection_vector': 'proxy'
                }
            ]
        }
        
        with patch('netstealth_analyzer.models.issues.Issue') as mock_issue_class:
            mock_issue = Mock(spec=Issue)
            mock_issue_class.return_value = mock_issue
            
            analyzer._process_pipeline_results(result, pipeline_data)
            
            mock_issue_class.assert_called_once()
            result.add_issue.assert_called_once_with(mock_issue)

    @pytest.mark.asyncio
    async def test_process_pipeline_results_with_traces(self, analyzer):
        """Test processing pipeline results with network traces."""
        result = Mock(spec=AnalysisResult)
        result.add_network_trace = Mock()
        
        pipeline_data = {
            'network_traces': [
                {
                    'trace_id': 'trace_1',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'source_ip': '192.168.1.1',
                    'destination_ip': '10.0.0.1',
                    'protocol': 'http',
                    'metadata': {}
                }
            ]
        }
        
        with patch('netstealth_analyzer.models.network.NetworkTrace') as mock_trace_class:
            mock_trace = Mock(spec=NetworkTrace)
            mock_trace_class.return_value = mock_trace
            
            analyzer._process_pipeline_results(result, pipeline_data)
            
            mock_trace_class.assert_called_once()
            result.add_network_trace.assert_called_once_with(mock_trace)

    @pytest.mark.asyncio
    async def test_process_pipeline_results_error_handling(self, analyzer):
        """Test error handling in pipeline result processing."""
        result = Mock(spec=AnalysisResult)
        result.add_issue = Mock(side_effect=Exception("Failed to add issue"))
        
        pipeline_data = {
            'issues': [{'invalid': 'data'}]
        }
        
        # Should not raise, just log warning
        with patch('netstealth_analyzer.models.issues.Issue', side_effect=Exception("Invalid issue data")):
            analyzer._process_pipeline_results(result, pipeline_data)


class TestNetStealthAnalyzerContextManager:
    """Test async context manager functionality."""

    @pytest.mark.asyncio
    async def test_context_manager_success(self, analyzer):
        """Test successful context manager usage."""
        async with analyzer as ctx:
            assert ctx == analyzer
            assert analyzer.is_initialized
        
        assert not analyzer.is_initialized

    @pytest.mark.asyncio
    async def test_context_manager_exception(self, analyzer, mock_components):
        """Test context manager with exception in body."""
        with pytest.raises(ValueError, match="Test exception"):
            async with analyzer as ctx:
                assert ctx == analyzer
                assert analyzer.is_initialized
                raise ValueError("Test exception")
        
        assert not analyzer.is_initialized


class TestNetStealthAnalyzerIntegration:
    """Integration tests for analyzer functionality."""

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, analyzer):
        """Test concurrent analyzer operations."""
        # Start multiple operations concurrently
        tasks = [
            analyzer.initialize(),
            asyncio.create_task(asyncio.sleep(0.01))  # Use a simple coroutine instead
        ]
        
        # Should handle concurrent access gracefully
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Initialization should succeed
        assert results[0] is None
        # Sleep should complete
        assert results[1] is None
