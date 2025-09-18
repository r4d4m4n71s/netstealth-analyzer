"""
Comprehensive tests for NetStealth Analyzer Pipeline Engine.

This test module provides extensive coverage for the PipelineEngine class,
including stage management, execution workflows, error handling, and monitoring.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timezone
from uuid import UUID
from typing import Dict, Any, List, AsyncIterator

from netstealth_analyzer.core.pipeline import (
    PipelineEngine, PipelineStatus, StageStatus, PipelineExecution, 
    StageExecution
)
from netstealth_analyzer.core.interfaces import (
    IComponent, IPipeline, ComponentStatus, ProcessingContext, 
    ProcessingResult, PipelineStage, ComponentMetadata, Priority
)
from netstealth_analyzer.core.events import EventBus, AnalysisEvent
from netstealth_analyzer.core.errors import ValidationError, TimeoutError
from netstealth_analyzer.models.enums import LogFormat


@pytest.fixture
def mock_event_bus():
    """Create mock event bus."""
    event_bus = Mock(spec=EventBus)
    event_bus.emit = AsyncMock()
    return event_bus


@pytest.fixture
def mock_component():
    """Create a mock component."""
    component = Mock(spec=IComponent)
    component.metadata = ComponentMetadata(
        name="test_component",
        version="1.0.0",
        description="Test component",
        author="Test",
        priority=Priority.NORMAL,
        tags=["test"],
        dependencies=[],
        supported_formats=[],
        configuration_schema={}
    )
    component.status = ComponentStatus.READY
    component.initialize = AsyncMock()
    component.shutdown = AsyncMock()
    component.process = AsyncMock(return_value=ProcessingResult(success=True, data={"result": "test"}))
    return component


@pytest.fixture
def mock_parser_component():
    """Create a mock parser component."""
    component = Mock(spec=IComponent)
    component.metadata = ComponentMetadata(
        name="test_parser",
        version="1.0.0",
        description="Test parser",
        author="Test",
        priority=Priority.HIGH,
        tags=["parser"],
        dependencies=[],
        supported_formats=[LogFormat.HAR],
        configuration_schema={}
    )
    component.status = ComponentStatus.READY
    component.initialize = AsyncMock()
    component.shutdown = AsyncMock()
    component.parse = AsyncMock(return_value=ProcessingResult(
        success=True, 
        data={"log_entries": [{"url": "test.com"}]}
    ))
    return component


@pytest.fixture
def mock_detector_component():
    """Create a mock detector component."""
    component = Mock(spec=IComponent)
    component.metadata = ComponentMetadata(
        name="test_detector",
        version="1.0.0",
        description="Test detector",
        author="Test",
        priority=Priority.NORMAL,
        tags=["detector"],
        dependencies=[],
        supported_formats=[],
        configuration_schema={}
    )
    component.status = ComponentStatus.READY
    component.initialize = AsyncMock()
    component.shutdown = AsyncMock()
    component.detect = AsyncMock(return_value=ProcessingResult(
        success=True,
        data={"issues": [{"type": "test_issue"}]}
    ))
    return component


@pytest.fixture
def mock_reporter_component():
    """Create a mock reporter component."""
    component = Mock(spec=IComponent)
    component.metadata = ComponentMetadata(
        name="test_reporter",
        version="1.0.0",
        description="Test reporter",
        author="Test",
        priority=Priority.LOW,
        tags=["reporter"],
        dependencies=[],
        supported_formats=[],
        configuration_schema={}
    )
    component.status = ComponentStatus.READY
    component.initialize = AsyncMock()
    component.shutdown = AsyncMock()
    component.generate_report = AsyncMock(return_value=ProcessingResult(
        success=True,
        data={"report": "test_report"}
    ))
    return component


@pytest.fixture
def sample_stage(mock_component):
    """Create a sample pipeline stage."""
    return PipelineStage(
        name="test_stage",
        component=mock_component,
        depends_on=[],
        parallel=False,
        optional=False,
        retry_count=0,
        timeout_seconds=30.0
    )


@pytest.fixture
def processing_context():
    """Create a processing context."""
    context = ProcessingContext()
    context.metadata = {
        "target_service": "test.com",
        "geography": "US"
    }
    return context


@pytest.fixture
def pipeline_engine(mock_event_bus):
    """Create a pipeline engine for testing."""
    return PipelineEngine(
        name="test_pipeline",
        event_bus=mock_event_bus,
        max_concurrent_stages=3,
        default_timeout=60.0
    )


class TestPipelineEngineInit:
    """Test PipelineEngine initialization."""

    def test_init_default_values(self):
        """Test pipeline engine initialization with default values."""
        engine = PipelineEngine()
        
        assert engine._name == "pipeline"
        assert engine._max_concurrent_stages == 5
        assert engine._default_timeout == 300.0
        assert engine._status == ComponentStatus.UNINITIALIZED
        assert engine._stages == {}
        assert engine._stage_order == []
        assert engine._dependency_graph == {}
        assert engine._current_execution is None
        assert engine._execution_history == []

    def test_init_custom_values(self, mock_event_bus):
        """Test pipeline engine initialization with custom values."""
        engine = PipelineEngine(
            name="custom_pipeline",
            event_bus=mock_event_bus,
            max_concurrent_stages=10,
            default_timeout=120.0
        )
        
        assert engine._name == "custom_pipeline"
        assert engine._event_bus == mock_event_bus
        assert engine._max_concurrent_stages == 10
        assert engine._default_timeout == 120.0

    def test_metadata_property(self, pipeline_engine):
        """Test metadata property."""
        metadata = pipeline_engine.metadata
        
        assert metadata.name == "test_pipeline"
        assert metadata.version == "2.0.0"
        assert metadata.description == "Pipeline processing engine"
        assert metadata.priority == Priority.HIGH
        assert "pipeline" in metadata.tags

    def test_status_property(self, pipeline_engine):
        """Test status property."""
        assert pipeline_engine.status == ComponentStatus.UNINITIALIZED
        
        pipeline_engine._status = ComponentStatus.READY
        assert pipeline_engine.status == ComponentStatus.READY

    def test_pipeline_status_property(self, pipeline_engine):
        """Test pipeline status property."""
        assert pipeline_engine.pipeline_status == PipelineStatus.IDLE
        
        # Create mock execution
        execution = PipelineExecution(status=PipelineStatus.RUNNING)
        pipeline_engine._current_execution = execution
        assert pipeline_engine.pipeline_status == PipelineStatus.RUNNING


class TestPipelineEngineLifecycle:
    """Test pipeline engine lifecycle management."""

    @pytest.mark.asyncio
    async def test_initialize_success(self, pipeline_engine, sample_stage):
        """Test successful initialization."""
        await pipeline_engine.add_stage(sample_stage)
        await pipeline_engine.initialize()
        
        assert pipeline_engine.status == ComponentStatus.READY
        sample_stage.component.initialize.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialize_with_config(self, pipeline_engine):
        """Test initialization with configuration."""
        config = {
            'max_concurrent_stages': 8,
            'default_timeout': 180.0
        }
        
        await pipeline_engine.initialize(config)
        
        assert pipeline_engine._max_concurrent_stages == 8
        assert pipeline_engine._default_timeout == 180.0
        assert pipeline_engine.status == ComponentStatus.READY

    @pytest.mark.asyncio
    async def test_initialize_idempotent(self, pipeline_engine):
        """Test that initialize can be called multiple times safely."""
        await pipeline_engine.initialize()
        assert pipeline_engine.status == ComponentStatus.READY
        
        # Call again
        await pipeline_engine.initialize()
        assert pipeline_engine.status == ComponentStatus.READY

    @pytest.mark.asyncio
    async def test_initialize_stage_failure(self, pipeline_engine, sample_stage):
        """Test initialization failure when stage fails."""
        sample_stage.component.initialize.side_effect = Exception("Stage init failed")
        await pipeline_engine.add_stage(sample_stage)
        
        with pytest.raises(Exception, match="Stage init failed"):
            await pipeline_engine.initialize()
        
        assert pipeline_engine.status == ComponentStatus.ERROR

    @pytest.mark.asyncio
    async def test_shutdown_success(self, pipeline_engine, sample_stage):
        """Test successful shutdown."""
        await pipeline_engine.add_stage(sample_stage)
        await pipeline_engine.initialize()
        await pipeline_engine.shutdown()
        
        assert pipeline_engine.status == ComponentStatus.DISPOSED
        sample_stage.component.shutdown.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_idempotent(self, pipeline_engine):
        """Test that shutdown can be called multiple times safely."""
        await pipeline_engine.initialize()
        await pipeline_engine.shutdown()
        assert pipeline_engine.status == ComponentStatus.DISPOSED
        
        # Call again
        await pipeline_engine.shutdown()
        assert pipeline_engine.status == ComponentStatus.DISPOSED

    @pytest.mark.asyncio
    async def test_shutdown_with_running_execution(self, pipeline_engine, sample_stage, processing_context):
        """Test shutdown with running execution."""
        await pipeline_engine.add_stage(sample_stage)
        await pipeline_engine.initialize()
        
        # Start execution in background
        execution_task = asyncio.create_task(
            pipeline_engine.execute({"test": "data"}, processing_context)
        )
        
        # Give it time to start
        await asyncio.sleep(0.01)
        
        # Shutdown should cancel execution
        await pipeline_engine.shutdown()
        
        # Wait for execution to complete
        result = await execution_task
        assert not result.success or pipeline_engine.status == ComponentStatus.DISPOSED


class TestPipelineEngineValidation:
    """Test pipeline configuration validation."""

    def test_validate_configuration_success(self, pipeline_engine):
        """Test successful configuration validation."""
        config = {
            'max_concurrent_stages': 5,
            'default_timeout': 120.0
        }
        
        assert pipeline_engine.validate_configuration(config) is True

    def test_validate_configuration_invalid_concurrent_stages(self, pipeline_engine):
        """Test validation failure with invalid concurrent stages."""
        config = {'max_concurrent_stages': 0}
        assert pipeline_engine.validate_configuration(config) is False
        
        config = {'max_concurrent_stages': -1}
        assert pipeline_engine.validate_configuration(config) is False
        
        config = {'max_concurrent_stages': "invalid"}
        assert pipeline_engine.validate_configuration(config) is False

    def test_validate_configuration_invalid_timeout(self, pipeline_engine):
        """Test validation failure with invalid timeout."""
        config = {'default_timeout': -1}
        assert pipeline_engine.validate_configuration(config) is False
        
        config = {'default_timeout': "invalid"}
        assert pipeline_engine.validate_configuration(config) is False

    def test_validate_configuration_exception(self, pipeline_engine):
        """Test validation with exception."""
        # Pass invalid config that causes exception
        assert pipeline_engine.validate_configuration(None) is False

    def test_validate_pipeline_success(self, pipeline_engine, sample_stage):
        """Test successful pipeline validation."""
        pipeline_engine._stages = {"test": sample_stage}
        pipeline_engine._dependency_graph = {"test": set()}
        pipeline_engine._stage_order = ["test"]
        
        assert pipeline_engine.validate_pipeline() is True

    def test_validate_pipeline_empty(self, pipeline_engine):
        """Test validation of empty pipeline."""
        assert pipeline_engine.validate_pipeline() is True

    def test_validate_pipeline_missing_dependency(self, pipeline_engine, sample_stage):
        """Test validation failure with missing dependency."""
        pipeline_engine._stages = {"test": sample_stage}
        pipeline_engine._dependency_graph = {"test": {"missing_dep"}}
        
        assert pipeline_engine.validate_pipeline() is False

    def test_validate_pipeline_invalid_component(self, pipeline_engine):
        """Test validation failure with invalid component."""
        invalid_component = Mock()
        del invalid_component.metadata  # Remove required attribute
        
        stage = PipelineStage(
            name="invalid_stage",
            component=invalid_component,
            depends_on=[],
            parallel=False,
            optional=False
        )
        
        pipeline_engine._stages = {"invalid": stage}
        pipeline_engine._dependency_graph = {"invalid": set()}
        
        assert pipeline_engine.validate_pipeline() is False

    def test_validate_pipeline_exception(self, pipeline_engine):
        """Test validation with exception."""
        # Create invalid state that causes exception
        pipeline_engine._stages = {"test": None}  # Invalid stage
        
        assert pipeline_engine.validate_pipeline() is False


class TestPipelineEngineStageManagement:
    """Test pipeline stage management."""

    @pytest.mark.asyncio
    async def test_add_stage_success(self, pipeline_engine, sample_stage, mock_event_bus):
        """Test successful stage addition."""
        await pipeline_engine.add_stage(sample_stage)
        
        assert "test_stage" in pipeline_engine._stages
        assert pipeline_engine._stages["test_stage"] == sample_stage
        assert "test_stage" in pipeline_engine._dependency_graph
        assert "test_stage" in pipeline_engine._stage_order
        
        mock_event_bus.emit.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_stage_empty_name(self, pipeline_engine, mock_component):
        """Test error with empty stage name."""
        stage = PipelineStage(
            name="",
            component=mock_component,
            depends_on=[],
            parallel=False,
            optional=False
        )
        
        with pytest.raises(ValidationError, match="Stage name cannot be empty"):
            await pipeline_engine.add_stage(stage)

    @pytest.mark.asyncio
    async def test_add_stage_duplicate_name(self, pipeline_engine, sample_stage):
        """Test error with duplicate stage name."""
        await pipeline_engine.add_stage(sample_stage)
        
        with pytest.raises(ValidationError, match="Stage 'test_stage' already exists"):
            await pipeline_engine.add_stage(sample_stage)

    @pytest.mark.asyncio
    async def test_add_stage_missing_dependency(self, pipeline_engine, mock_component):
        """Test error with missing dependency."""
        stage = PipelineStage(
            name="dependent_stage",
            component=mock_component,
            depends_on=["missing_stage"],
            parallel=False,
            optional=False
        )
        
        with pytest.raises(ValidationError, match="Dependency 'missing_stage' not found"):
            await pipeline_engine.add_stage(stage)

    @pytest.mark.asyncio
    async def test_add_stage_with_dependencies(self, pipeline_engine, mock_component):
        """Test adding stage with valid dependencies."""
        # Add first stage
        stage1 = PipelineStage(
            name="stage1",
            component=mock_component,
            depends_on=[],
            parallel=False,
            optional=False
        )
        await pipeline_engine.add_stage(stage1)
        
        # Add dependent stage
        stage2 = PipelineStage(
            name="stage2",
            component=mock_component,
            depends_on=["stage1"],
            parallel=False,
            optional=False
        )
        await pipeline_engine.add_stage(stage2)
        
        assert pipeline_engine._dependency_graph["stage2"] == {"stage1"}
        assert pipeline_engine._stage_order == ["stage1", "stage2"]

    @pytest.mark.asyncio
    async def test_add_stage_while_running(self, pipeline_engine, sample_stage):
        """Test error when adding stage while pipeline is running."""
        # Create mock running execution
        execution = PipelineExecution(status=PipelineStatus.RUNNING)
        pipeline_engine._current_execution = execution
        
        with pytest.raises(ValidationError, match="Cannot modify pipeline while execution is running"):
            await pipeline_engine.add_stage(sample_stage)

    @pytest.mark.asyncio
    async def test_remove_stage_success(self, pipeline_engine, sample_stage):
        """Test successful stage removal."""
        await pipeline_engine.add_stage(sample_stage)
        
        result = await pipeline_engine.remove_stage("test_stage")
        
        assert result is True
        assert "test_stage" not in pipeline_engine._stages
        assert "test_stage" not in pipeline_engine._dependency_graph
        assert "test_stage" not in pipeline_engine._stage_order

    @pytest.mark.asyncio
    async def test_remove_stage_not_found(self, pipeline_engine):
        """Test removing non-existent stage."""
        result = await pipeline_engine.remove_stage("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_remove_stage_with_dependents(self, pipeline_engine, mock_component):
        """Test error when removing stage with dependents."""
        # Add stages with dependency
        stage1 = PipelineStage(name="stage1", component=mock_component, depends_on=[])
        stage2 = PipelineStage(name="stage2", component=mock_component, depends_on=["stage1"])
        
        await pipeline_engine.add_stage(stage1)
        await pipeline_engine.add_stage(stage2)
        
        with pytest.raises(ValidationError, match="Cannot remove stage 'stage1': stages \\['stage2'\\] depend on it"):
            await pipeline_engine.remove_stage("stage1")

    @pytest.mark.asyncio
    async def test_remove_stage_while_running(self, pipeline_engine, sample_stage):
        """Test error when removing stage while pipeline is running."""
        await pipeline_engine.add_stage(sample_stage)
        
        # Create mock running execution
        execution = PipelineExecution(status=PipelineStatus.RUNNING)
        pipeline_engine._current_execution = execution
        
        with pytest.raises(ValidationError, match="Cannot modify pipeline while execution is running"):
            await pipeline_engine.remove_stage("test_stage")

    def test_get_stage_order(self, pipeline_engine):
        """Test getting stage execution order."""
        pipeline_engine._stage_order = ["stage1", "stage2", "stage3"]
        
        order = pipeline_engine.get_stage_order()
        
        assert order == ["stage1", "stage2", "stage3"]
        assert order is not pipeline_engine._stage_order  # Should be a copy

    @pytest.mark.asyncio
    async def test_rebuild_stage_order_complex_dependencies(self, pipeline_engine, mock_component):
        """Test rebuilding stage order with complex dependencies."""
        # Create stages with complex dependency graph
        stages = [
            PipelineStage(name="A", component=mock_component, depends_on=[]),
            PipelineStage(name="B", component=mock_component, depends_on=["A"]),
            PipelineStage(name="C", component=mock_component, depends_on=["A"]),
            PipelineStage(name="D", component=mock_component, depends_on=["B", "C"]),
        ]
        
        # Add stages in dependency order (A first, then B and C, then D)
        await pipeline_engine.add_stage(stages[0])  # A
        await pipeline_engine.add_stage(stages[1])  # B
        await pipeline_engine.add_stage(stages[2])  # C
        await pipeline_engine.add_stage(stages[3])  # D
        
        # Check that order is correct
        order = pipeline_engine.get_stage_order()
        assert order.index("A") < order.index("B")
        assert order.index("A") < order.index("C")
        assert order.index("B") < order.index("D")
        assert order.index("C") < order.index("D")

    @pytest.mark.asyncio
    async def test_circular_dependency_detection(self, pipeline_engine, mock_component):
        """Test detection of circular dependencies."""
        # Add stages that will create circular dependency
        stage1 = PipelineStage(name="stage1", component=mock_component, depends_on=[])
        await pipeline_engine.add_stage(stage1)
        
        stage2 = PipelineStage(name="stage2", component=mock_component, depends_on=["stage1"])
        await pipeline_engine.add_stage(stage2)
        
        # Manually create circular dependency (simulating invalid state)
        pipeline_engine._dependency_graph["stage1"] = {"stage2"}
        
        assert pipeline_engine._has_circular_dependencies() is True


class TestPipelineEngineExecution:
    """Test pipeline execution functionality."""

    @pytest.mark.asyncio
    async def test_execute_empty_pipeline(self, pipeline_engine, processing_context):
        """Test execution with no stages."""
        result = await pipeline_engine.execute({"test": "data"}, processing_context)
        
        assert not result.success
        assert isinstance(result.error, ValidationError)
        assert "No stages configured" in str(result.error)

    @pytest.mark.asyncio
    async def test_execute_invalid_pipeline(self, pipeline_engine, processing_context, sample_stage):
        """Test execution with invalid pipeline."""
        await pipeline_engine.add_stage(sample_stage)
        
        # Make pipeline invalid
        pipeline_engine._dependency_graph["test_stage"] = {"missing_dep"}
        
        result = await pipeline_engine.execute({"test": "data"}, processing_context)
        
        assert not result.success
        assert isinstance(result.error, ValidationError)
        assert "Pipeline configuration is invalid" in str(result.error)

    @pytest.mark.asyncio
    async def test_execute_single_stage_success(self, pipeline_engine, sample_stage, processing_context, mock_event_bus):
        """Test successful execution with single stage."""
        await pipeline_engine.add_stage(sample_stage)
        
        result = await pipeline_engine.execute({"test": "data"}, processing_context)
        
        assert result.success
        assert result.data is not None
        assert "input" in result.data
        assert result.data["input"] == {"test": "data"}
        
        # Verify events were emitted
        assert mock_event_bus.emit.call_count >= 2  # At least start and complete events

    @pytest.mark.asyncio
    async def test_execute_multiple_stages_success(self, pipeline_engine, processing_context, mock_event_bus):
        """Test successful execution with multiple stages."""
        # Create multiple components
        comp1 = Mock(spec=IComponent)
        comp1.metadata = ComponentMetadata(name="comp1", version="1.0", description="", author="", priority=Priority.HIGH)
        comp1.status = ComponentStatus.READY
        comp1.initialize = AsyncMock()
        comp1.shutdown = AsyncMock()
        comp1.process = AsyncMock(return_value=ProcessingResult(success=True, data={"stage1": "result"}))
        
        comp2 = Mock(spec=IComponent)
        comp2.metadata = ComponentMetadata(name="comp2", version="1.0", description="", author="", priority=Priority.NORMAL)
        comp2.status = ComponentStatus.READY
        comp2.initialize = AsyncMock()
        comp2.shutdown = AsyncMock()
        comp2.process = AsyncMock(return_value=ProcessingResult(success=True, data={"stage2": "result"}))
        
        # Create stages
        stage1 = PipelineStage(name="stage1", component=comp1, depends_on=[])
        stage2 = PipelineStage(name="stage2", component=comp2, depends_on=["stage1"])
        
        await pipeline_engine.add_stage(stage1)
        await pipeline_engine.add_stage(stage2)
        
        result = await pipeline_engine.execute({"test": "data"}, processing_context)
        
        assert result.success
        assert "stage1" in result.data
        assert "stage2" in result.data

    @pytest.mark.asyncio
    async def test_execute_stage_failure_required(self, pipeline_engine, processing_context):
        """Test execution with required stage failure."""
        # Create failing component
        failing_comp = Mock(spec=IComponent)
        failing_comp.metadata = ComponentMetadata(name="failing", version="1.0", description="", author="", priority=Priority.HIGH)
        failing_comp.status = ComponentStatus.READY
        failing_comp.initialize = AsyncMock()
        failing_comp.shutdown = AsyncMock()
        failing_comp.process = AsyncMock(side_effect=Exception("Stage failed"))
        
        stage = PipelineStage(
            name="failing_stage",
            component=failing_comp,
            depends_on=[],
            optional=False  # Required stage
        )
        
        await pipeline_engine.add_stage(stage)
        
        result = await pipeline_engine.execute({"test": "data"}, processing_context)
        
        assert not result.success
        assert "Stage failed" in str(result.error)

    @pytest.mark.asyncio
    async def test_execute_stage_failure_optional(self, pipeline_engine, processing_context):
        """Test execution with optional stage failure."""
        # Create failing component
        failing_comp = Mock(spec=IComponent)
        failing_comp.metadata = ComponentMetadata(name="failing", version="1.0", description="", author="", priority=Priority.HIGH)
        failing_comp.status = ComponentStatus.READY
        failing_comp.initialize = AsyncMock()
        failing_comp.shutdown = AsyncMock()
        failing_comp.process = AsyncMock(side_effect=Exception("Stage failed"))
        
        stage = PipelineStage(
            name="failing_stage",
            component=failing_comp,
            depends_on=[],
            optional=True  # Optional stage
        )
        
        await pipeline_engine.add_stage(stage)
        
        result = await pipeline_engine.execute({"test": "data"}, processing_context)
        
        assert result.success  # Should succeed despite optional stage failure

    @pytest.mark.asyncio
    async def test_execute_stage_timeout(self, pipeline_engine, processing_context):
        """Test execution with stage timeout."""
        # Create slow component
        slow_comp = Mock(spec=IComponent)
        slow_comp.metadata = ComponentMetadata(name="slow", version="1.0", description="", author="", priority=Priority.HIGH)
        slow_comp.status = ComponentStatus.READY
        slow_comp.initialize = AsyncMock()
        slow_comp.shutdown = AsyncMock()
        
        async def slow_process(*args, **kwargs):
            await asyncio.sleep(2.0)  # Longer than timeout
            return ProcessingResult(success=True, data={})
        
        slow_comp.process = slow_process
        
        stage = PipelineStage(
            name="slow_stage",
            component=slow_comp,
            depends_on=[],
            timeout_seconds=0.1  # Very short timeout
        )
        
        await pipeline_engine.add_stage(stage)
        
        result = await pipeline_engine.execute({"test": "data"}, processing_context)
        
        assert not result.success
        assert isinstance(result.error, TimeoutError)

    @pytest.mark.asyncio
    async def test_execute_stage_retry(self, pipeline_engine, processing_context):
        """Test stage retry functionality."""
        # Create component that fails first time, succeeds second time
        retry_comp = Mock(spec=IComponent)
        retry_comp.metadata = ComponentMetadata(name="retry", version="1.0", description="", author="", priority=Priority.HIGH)
        retry_comp.status = ComponentStatus.READY
        retry_comp.initialize = AsyncMock()
        retry_comp.shutdown = AsyncMock()
        
        call_count = 0
        async def retry_process(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("First attempt fails")
            return ProcessingResult(success=True, data={"retry": "success"})
        
        retry_comp.process = retry_process
        
        stage = PipelineStage(
            name="retry_stage",
            component=retry_comp,
            depends_on=[],
            retry_count=1  # Allow one retry
        )
        
        await pipeline_engine.add_stage(stage)
        
        result = await pipeline_engine.execute({"test": "data"}, processing_context)
        
        assert result.success
        assert call_count == 2  # Should have been called twice

    @pytest.mark.asyncio
    async def test_execute_with_cancellation(self, pipeline_engine, processing_context):
        """Test execution cancellation."""
        # Create slow component
        slow_comp = Mock(spec=IComponent)
        slow_comp.metadata = ComponentMetadata(name="slow", version="1.0", description="", author="", priority=Priority.HIGH)
        slow_comp.status = ComponentStatus.READY
        slow_comp.initialize = AsyncMock()
        slow_comp.shutdown = AsyncMock()
        
        async def slow_process(*args, **kwargs):
            await asyncio.sleep(1.0)
            return ProcessingResult(success=True, data={})
        
        slow_comp.process = slow_process
        
        stage = PipelineStage(name="slow_stage", component=slow_comp, depends_on=[])
        await pipeline_engine.add_stage(stage)
        
        # Start execution
        execution_task = asyncio.create_task(
            pipeline_engine.execute({"test": "data"}, processing_context)
        )
        
        # Cancel after short delay
        await asyncio.sleep(0.01)
        await pipeline_engine.cancel_execution()
        
        result = await execution_task
        
        assert not result.success
        assert "cancelled" in str(result.error).lower()


class TestPipelineEngineStreamingExecution:
    """Test pipeline streaming execution."""

    @pytest.mark.asyncio
    async def test_execute_streaming_empty_pipeline(self, pipeline_engine, processing_context):
        """Test streaming execution with no stages."""
        async def empty_stream():
            yield {"test": "data"}
        
        with pytest.raises(ValidationError, match="No stages configured"):
            async for _ in pipeline_engine.execute_streaming(empty_stream(), processing_context):
                pass

    @pytest.mark.asyncio
    async def test_execute_streaming_success(self, pipeline_engine, sample_stage, processing_context):
        """Test successful streaming execution."""
        await pipeline_engine.add_stage(sample_stage)
        
        async def test_stream():
            for i in range(3):
                yield {"item": i}
        
        results = []
        async for result in pipeline_engine.execute_streaming(test_stream(), processing_context):
            results.append(result)
        
        assert len(results) == 3
        for i, result in enumerate(results):
            assert result["input"]["item"] == i

    @pytest.mark.asyncio
    async def test_execute_streaming_with_error(self, pipeline_engine, processing_context):
        """Test streaming execution with error handling."""
        # Create failing component
        failing_comp = Mock(spec=IComponent)
        failing_comp.metadata = ComponentMetadata(name="failing", version="1.0", description="", author="", priority=Priority.HIGH)
        failing_comp.status = ComponentStatus.READY
        failing_comp.initialize = AsyncMock()
        failing_comp.shutdown = AsyncMock()
        failing_comp.process = AsyncMock(side_effect=Exception("Stream processing failed"))
        
        stage = PipelineStage(
            name="failing_stage",
            component=failing_comp,
            depends_on=[],
            optional=True  # Make it optional so streaming continues
        )
        
        await pipeline_engine.add_stage(stage)
        
        async def test_stream():
            for i in range(2):
                yield {"item": i}
        
        results = []
        async for result in pipeline_engine.execute_streaming(test_stream(), processing_context):
            results.append(result)
        
        # Should still get results despite errors
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_execute_streaming_with_cancellation(self, pipeline_engine, sample_stage, processing_context):
        """Test streaming execution cancellation."""
        await pipeline_engine.add_stage(sample_stage)
        
        async def test_stream():
            for i in range(10):  # Long stream
                yield {"item": i}
                await asyncio.sleep(0.01)  # Small delay
        
        results = []
        stream_gen = pipeline_engine.execute_streaming(test_stream(), processing_context)
        
        # Get first result
        result = await stream_gen.__anext__()
        results.append(result)
        
        # Cancel execution
        await pipeline_engine.cancel_execution()
        
        # Try to get more results - should stop
        try:
            async for result in stream_gen:
                results.append(result)
                if len(results) > 5:  # Safety break
                    break
        except StopAsyncIteration:
            pass
        
        # Should have stopped early due to cancellation
        assert len(results) < 10


class TestPipelineEngineControlMethods:
    """Test pipeline control methods."""

    @pytest.mark.asyncio
    async def test_pause_execution(self, pipeline_engine):
        """Test pausing pipeline execution."""
        # Create mock execution
        execution = PipelineExecution(status=PipelineStatus.RUNNING)
        pipeline_engine._current_execution = execution
        
        await pipeline_engine.pause_execution()
        
        assert execution.status == PipelineStatus.PAUSED
        assert not pipeline_engine._pause_event.is_set()

    @pytest.mark.asyncio
    async def test_pause_execution_no_current(self, pipeline_engine):
        """Test pausing when no execution is running."""
        # Should not raise error
        await pipeline_engine.pause_execution()

    @pytest.mark.asyncio
    async def test_resume_execution(self, pipeline_engine):
        """Test resuming paused pipeline execution."""
        # Create mock paused execution
        execution = PipelineExecution(status=PipelineStatus.PAUSED)
        pipeline_engine._current_execution = execution
        pipeline_engine._pause_event.clear()
        
        await pipeline_engine.resume_execution()
        
        assert execution.status == PipelineStatus.RUNNING
        assert pipeline_engine._pause_event.is_set()

    @pytest.mark.asyncio
    async def test_resume_execution_no_current(self, pipeline_engine):
        """Test resuming when no execution is paused."""
        # Should not raise error
        await pipeline_engine.resume_execution()

    @pytest.mark.asyncio
    async def test_cancel_execution(self, pipeline_engine):
        """Test cancelling pipeline execution."""
        # Create mock running execution
        execution = PipelineExecution(status=PipelineStatus.RUNNING)
        pipeline_engine._current_execution = execution
        
        await pipeline_engine.cancel_execution()
        
        assert execution.status == PipelineStatus.STOPPING
        assert pipeline_engine._cancel_event.is_set()

    @pytest.mark.asyncio
    async def test_cancel_execution_paused(self, pipeline_engine):
        """Test cancelling paused pipeline execution."""
        # Create mock paused execution
        execution = PipelineExecution(status=PipelineStatus.PAUSED)
        pipeline_engine._current_execution = execution
        
        await pipeline_engine.cancel_execution()
        
        assert execution.status == PipelineStatus.STOPPING
        assert pipeline_engine._cancel_event.is_set()


class TestPipelineEngineMonitoring:
    """Test pipeline monitoring and statistics."""

    def test_get_health_status(self, pipeline_engine, sample_stage):
        """Test getting pipeline health status."""
        pipeline_engine._status = ComponentStatus.READY
        pipeline_engine._stages = {"test": sample_stage}
        
        health = pipeline_engine.get_health_status()
        
        assert health['status'] == ComponentStatus.READY.value
        assert health['pipeline_status'] == PipelineStatus.IDLE.value
        assert health['total_stages'] == 1
        assert health['ready_stages'] == 1
        assert health['current_execution_id'] is None
        assert 'stats' in health

    def test_get_health_status_with_execution(self, pipeline_engine):
        """Test health status with current execution."""
        execution = PipelineExecution(status=PipelineStatus.RUNNING)
        pipeline_engine._current_execution = execution
        
        health = pipeline_engine.get_health_status()
        
        assert health['current_execution_id'] == str(execution.execution_id)

    def test_get_execution_history(self, pipeline_engine):
        """Test getting execution history."""
        # Add some mock executions
        exec1 = PipelineExecution(status=PipelineStatus.COMPLETED)
        exec2 = PipelineExecution(status=PipelineStatus.FAILED)
        pipeline_engine._execution_history = [exec1, exec2]
        
        history = pipeline_engine.get_execution_history()
        
        assert len(history) == 2
        assert history[0] == exec1
        assert history[1] == exec2
        assert history is not pipeline_engine._execution_history  # Should be copy

    def test_get_execution_history_with_limit(self, pipeline_engine):
        """Test getting execution history with limit."""
        # Add multiple mock executions
        executions = [PipelineExecution(status=PipelineStatus.COMPLETED) for _ in range(5)]
        pipeline_engine._execution_history = executions
        
        history = pipeline_engine.get_execution_history(limit=3)
        
        assert len(history) == 3
        assert history == executions[-3:]  # Should get last 3

    def test_get_statistics(self, pipeline_engine, sample_stage):
        """Test getting comprehensive statistics."""
        pipeline_engine._stages = {"test": sample_stage}
        pipeline_engine._stats = {
            'total_executions': 10,
            'successful_executions': 8,
            'failed_executions': 2,
            'cancelled_executions': 0,
            'total_stages_executed': 80,
            'average_execution_time_ms': 1500.0,
        }
        
        stats = pipeline_engine.get_statistics()
        
        assert 'pipeline_stats' in stats
        assert 'current_execution' in stats
        assert 'stage_stats' in stats
        
        assert stats['pipeline_stats']['total_executions'] == 10
        assert stats['pipeline_stats']['successful_executions'] == 8
        assert stats['stage_stats']['test']['component_type'] == 'Mock'

    def test_get_statistics_with_current_execution(self, pipeline_engine):
        """Test statistics with current execution."""
        execution = PipelineExecution(
            status=PipelineStatus.RUNNING,
            stages={"stage1": StageExecution(stage=Mock()), "stage2": StageExecution(stage=Mock())}
        )
        execution.stages["stage1"].status = StageStatus.COMPLETED
        pipeline_engine._current_execution = execution
        
        stats = pipeline_engine.get_statistics()
        
        current_exec = stats['current_execution']
        assert current_exec['status'] == PipelineStatus.RUNNING.value
        assert current_exec['completed_stages'] == 1
        assert current_exec['total_stages'] == 2

    def test_clear_history(self, pipeline_engine):
        """Test clearing execution history."""
        # Add some mock executions
        executions = [PipelineExecution(status=PipelineStatus.COMPLETED) for _ in range(3)]
        pipeline_engine._execution_history = executions
        
        pipeline_engine.clear_history()
        
        assert len(pipeline_engine._execution_history) == 0

    def test_update_average_execution_time(self, pipeline_engine):
        """Test updating average execution time."""
        # First execution
        pipeline_engine._stats['successful_executions'] = 1
        pipeline_engine._update_average_execution_time(1000)
        assert pipeline_engine._stats['average_execution_time_ms'] == 1000.0
        
        # Second execution
        pipeline_engine._stats['successful_executions'] = 2
        pipeline_engine._update_average_execution_time(2000)
        assert pipeline_engine._stats['average_execution_time_ms'] == 1500.0
        
        # Third execution
        pipeline_engine._stats['successful_executions'] = 3
        pipeline_engine._update_average_execution_time(3000)
        assert pipeline_engine._stats['average_execution_time_ms'] == 2000.0


class TestPipelineEngineComponentInterfaces:
    """Test pipeline engine component interface handling."""

    @pytest.mark.asyncio
    async def test_call_stage_component_parser(self, pipeline_engine, mock_parser_component, processing_context):
        """Test calling parser component."""
        processing_context.file_path = "/test/file.har"
        
        result = await pipeline_engine._call_stage_component(
            mock_parser_component, {"test": "data"}, processing_context
        )
        
        mock_parser_component.parse.assert_called_once_with("/test/file.har", processing_context)
        assert result.success

    @pytest.mark.asyncio
    async def test_call_stage_component_detector(self, pipeline_engine, mock_detector_component, processing_context):
        """Test calling detector component."""
        input_data = {"log_entries": [{"url": "test.com"}]}
        
        result = await pipeline_engine._call_stage_component(
            mock_detector_component, input_data, processing_context
        )
        
        mock_detector_component.detect.assert_called_once_with([{"url": "test.com"}], processing_context)
        assert result.success

    @pytest.mark.asyncio
    async def test_call_stage_component_reporter(self, pipeline_engine, mock_reporter_component, processing_context):
        """Test calling reporter component."""
        input_data = {"issues": [{"type": "test"}]}
        
        result = await pipeline_engine._call_stage_component(
            mock_reporter_component, input_data, processing_context
        )
        
        mock_reporter_component.generate_report.assert_called_once()
        assert result.success

    @pytest.mark.asyncio
    async def test_call_stage_component_generic_processor(self, pipeline_engine, mock_component, processing_context):
        """Test calling generic processor component."""
        input_data = {"test": "data"}
        
        result = await pipeline_engine._call_stage_component(
            mock_component, input_data, processing_context
        )
        
        mock_component.process.assert_called_once_with(input_data, processing_context)
        assert result.success

    @pytest.mark.asyncio
    async def test_call_stage_component_unsupported(self, pipeline_engine, processing_context):
        """Test calling component with unsupported interface."""
        unsupported_comp = Mock(spec=IComponent)
        unsupported_comp.metadata = ComponentMetadata(name="unsupported", version="1.0", description="", author="", priority=Priority.NORMAL)
        # Remove all supported methods
        
        with pytest.raises(ValidationError, match="Component .* has no supported interface"):
            await pipeline_engine._call_stage_component(
                unsupported_comp, {"test": "data"}, processing_context
            )


class TestPipelineEngineUtilityMethods:
    """Test pipeline engine utility methods."""

    def test_check_dependencies_met_success(self, pipeline_engine):
        """Test checking dependencies when all are met."""
        execution = PipelineExecution()
        execution.stages = {
            "stage1": StageExecution(stage=Mock(), status=StageStatus.COMPLETED),
            "stage2": StageExecution(stage=Mock(), status=StageStatus.COMPLETED),
            "stage3": StageExecution(stage=Mock(), status=StageStatus.PENDING)
        }
        
        pipeline_engine._dependency_graph = {"stage3": {"stage1", "stage2"}}
        
        result = pipeline_engine._check_dependencies_met("stage3", execution)
        assert result is True

    def test_check_dependencies_met_failure(self, pipeline_engine):
        """Test checking dependencies when some are not met."""
        execution = PipelineExecution()
        execution.stages = {
            "stage1": StageExecution(stage=Mock(), status=StageStatus.COMPLETED),
            "stage2": StageExecution(stage=Mock(), status=StageStatus.FAILED),
            "stage3": StageExecution(stage=Mock(), status=StageStatus.PENDING)
        }
        
        pipeline_engine._dependency_graph = {"stage3": {"stage1", "stage2"}}
        
        result = pipeline_engine._check_dependencies_met("stage3", execution)
        assert result is False

    def test_check_dependencies_met_no_dependencies(self, pipeline_engine):
        """Test checking dependencies when stage has none."""
        execution = PipelineExecution()
        execution.stages = {
            "stage1": StageExecution(stage=Mock(), status=StageStatus.PENDING)
        }
        
        pipeline_engine._dependency_graph = {"stage1": set()}
        
        result = pipeline_engine._check_dependencies_met("stage1", execution)
        assert result is True

    def test_get_stage_levels_simple(self, pipeline_engine):
        """Test getting stage levels with simple dependencies."""
        pipeline_engine._stage_order = ["A", "B", "C"]
        pipeline_engine._dependency_graph = {
            "A": set(),
            "B": {"A"},
            "C": {"B"}
        }
        
        levels = pipeline_engine._get_stage_levels()
        
        assert len(levels) == 3
        assert levels[0] == ["A"]
        assert levels[1] == ["B"]
        assert levels[2] == ["C"]

    def test_get_stage_levels_parallel(self, pipeline_engine):
        """Test getting stage levels with parallel stages."""
        pipeline_engine._stage_order = ["A", "B", "C", "D"]
        pipeline_engine._dependency_graph = {
            "A": set(),
            "B": {"A"},
            "C": {"A"},
            "D": {"B", "C"}
        }
        
        levels = pipeline_engine._get_stage_levels()
        
        assert len(levels) == 3
        assert levels[0] == ["A"]
        assert set(levels[1]) == {"B", "C"}  # B and C can run in parallel
        assert levels[2] == ["D"]

    def test_get_stage_levels_invalid_configuration(self, pipeline_engine):
        """Test getting stage levels with invalid configuration."""
        pipeline_engine._stage_order = ["A", "B"]
        pipeline_engine._dependency_graph = {
            "A": {"B"},  # Circular dependency
            "B": {"A"}
        }
        
        with pytest.raises(ValidationError, match="Circular dependency or invalid pipeline configuration"):
            pipeline_engine._get_stage_levels()


class TestStageExecutionDataClass:
    """Test StageExecution dataclass functionality."""

    def test_stage_execution_duration_ms(self):
        """Test duration calculation."""
        stage_exec = StageExecution(stage=Mock())
        
        # No times set
        assert stage_exec.duration_ms is None
        
        # Set start time only
        stage_exec.start_time = datetime.now(timezone.utc)
        assert stage_exec.duration_ms is None
        
        # Set both times with proper microsecond handling
        start = datetime.now(timezone.utc)
        # Add 500ms by using timedelta to avoid microsecond overflow
        from datetime import timedelta
        end = start + timedelta(milliseconds=500)
        stage_exec.start_time = start
        stage_exec.end_time = end
        
        duration = stage_exec.duration_ms
        assert duration is not None
        assert 400 <= duration <= 600  # Allow some variance

    def test_stage_execution_is_terminal(self):
        """Test terminal status checking."""
        stage_exec = StageExecution(stage=Mock())
        
        # Non-terminal statuses
        for status in [StageStatus.PENDING, StageStatus.READY, StageStatus.RUNNING]:
            stage_exec.status = status
            assert not stage_exec.is_terminal
        
        # Terminal statuses
        for status in [StageStatus.COMPLETED, StageStatus.FAILED, StageStatus.SKIPPED, StageStatus.CANCELLED]:
            stage_exec.status = status
            assert stage_exec.is_terminal


class TestPipelineExecutionDataClass:
    """Test PipelineExecution dataclass functionality."""

    def test_pipeline_execution_duration_ms(self):
        """Test duration calculation."""
        pipeline_exec = PipelineExecution()
        
        # No times set
        assert pipeline_exec.duration_ms is None
        
        # Set both times with proper microsecond handling
        start = datetime.now(timezone.utc)
        # Add 750ms by using timedelta to avoid microsecond overflow
        from datetime import timedelta
        end = start + timedelta(milliseconds=750)
        pipeline_exec.start_time = start
        pipeline_exec.end_time = end
        
        duration = pipeline_exec.duration_ms
        assert duration is not None
        assert 650 <= duration <= 850  # Allow some variance

    def test_pipeline_execution_stage_counts(self):
        """Test stage counting properties."""
        pipeline_exec = PipelineExecution()
        pipeline_exec.stages = {
            "stage1": StageExecution(stage=Mock(), status=StageStatus.COMPLETED),
            "stage2": StageExecution(stage=Mock(), status=StageStatus.FAILED),
            "stage3": StageExecution(stage=Mock(), status=StageStatus.RUNNING),
            "stage4": StageExecution(stage=Mock(), status=StageStatus.COMPLETED),
        }
        
        assert pipeline_exec.completed_stages == 2
        assert pipeline_exec.failed_stages == 1
        assert pipeline_exec.total_stages == 4
