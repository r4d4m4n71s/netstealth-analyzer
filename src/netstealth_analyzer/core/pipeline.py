"""
Pipeline processing engine for NetStealth Analyzer.

This module provides the core pipeline orchestration system that coordinates
the execution of parsers, detectors, and reporters in a structured workflow.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import asyncio
from typing import Any, Dict, List, Optional, Set, AsyncIterator, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4
from enum import Enum, auto
import logging
from contextlib import asynccontextmanager

from .interfaces import (
    IComponent, IPipeline, ComponentStatus, ProcessingContext, 
    ProcessingResult, PipelineStage, ComponentMetadata, Priority
)
from .events import (
    EventBus, AnalysisEvent, StageData, ProgressData, ErrorData,
    get_event_bus, emit_progress
)
from .errors import (
    NetStealthError, ErrorCategory, ErrorSeverity, RecoveryStrategy,
    ErrorContext, handle_error, TimeoutError, ValidationError
)
from ..compatibility import TaskGroup, override

logger = logging.getLogger(__name__)


class PipelineStatus(Enum):
    """Status of pipeline execution."""
    
    IDLE = "idle"                      # Pipeline not running
    INITIALIZING = "initializing"      # Pipeline being initialized
    RUNNING = "running"                # Pipeline actively executing
    PAUSED = "paused"                  # Pipeline execution paused
    STOPPING = "stopping"              # Pipeline being stopped
    COMPLETED = "completed"            # Pipeline completed successfully
    FAILED = "failed"                  # Pipeline failed with error
    CANCELLED = "cancelled"            # Pipeline was cancelled


class StageStatus(Enum):
    """Status of individual pipeline stages."""
    
    PENDING = "pending"                # Stage waiting to execute
    READY = "ready"                    # Stage ready to execute
    RUNNING = "running"                # Stage currently executing
    COMPLETED = "completed"            # Stage completed successfully
    FAILED = "failed"                  # Stage failed with error
    SKIPPED = "skipped"                # Stage was skipped
    CANCELLED = "cancelled"            # Stage was cancelled


@dataclass
class StageExecution:
    """Tracks execution state of a pipeline stage."""
    
    stage: PipelineStage
    status: StageStatus = StageStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    result: Optional[ProcessingResult] = None
    error: Optional[Exception] = None
    retry_count: int = 0
    dependencies_met: bool = False
    
    @property
    def duration_ms(self) -> Optional[int]:
        """Get execution duration in milliseconds."""
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            return int(delta.total_seconds() * 1000)
        return None
    
    @property
    def is_terminal(self) -> bool:
        """Check if stage is in a terminal state."""
        return self.status in {
            StageStatus.COMPLETED,
            StageStatus.FAILED,
            StageStatus.SKIPPED,
            StageStatus.CANCELLED
        }


@dataclass
class PipelineExecution:
    """Tracks execution state of entire pipeline."""
    
    execution_id: UUID = field(default_factory=uuid4)
    status: PipelineStatus = PipelineStatus.IDLE
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    stages: Dict[str, StageExecution] = field(default_factory=dict)
    context: Optional[ProcessingContext] = None
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[Exception] = field(default_factory=list)
    
    @property
    def duration_ms(self) -> Optional[int]:
        """Get total execution duration in milliseconds."""
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            return int(delta.total_seconds() * 1000)
        return None
    
    @property
    def completed_stages(self) -> int:
        """Get number of completed stages."""
        return sum(1 for stage in self.stages.values() 
                  if stage.status == StageStatus.COMPLETED)
    
    @property
    def failed_stages(self) -> int:
        """Get number of failed stages."""
        return sum(1 for stage in self.stages.values() 
                  if stage.status == StageStatus.FAILED)
    
    @property
    def total_stages(self) -> int:
        """Get total number of stages."""
        return len(self.stages)


class PipelineEngine(IComponent):
    """
    Core pipeline processing engine.
    
    Orchestrates the execution of multiple stages (parsers, detectors, reporters)
    in a coordinated workflow with dependency management, error handling, and
    progress tracking.
    """
    
    def __init__(
        self,
        name: str = "pipeline",
        event_bus: Optional[EventBus] = None,
        max_concurrent_stages: int = 5,
        default_timeout: float = 300.0
    ):
        self._name = name
        self._event_bus = event_bus or get_event_bus()
        self._max_concurrent_stages = max_concurrent_stages
        self._default_timeout = default_timeout
        
        # Pipeline configuration
        self._stages: Dict[str, PipelineStage] = {}
        self._stage_order: List[str] = []
        self._dependency_graph: Dict[str, Set[str]] = {}
        
        # Execution state
        self._status = ComponentStatus.UNINITIALIZED
        self._current_execution: Optional[PipelineExecution] = None
        self._execution_history: List[PipelineExecution] = []
        self._max_history = 100
        
        # Cancellation support
        self._cancel_event = asyncio.Event()
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # Start unpaused
        
        # Statistics
        self._stats = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'cancelled_executions': 0,
            'total_stages_executed': 0,
            'average_execution_time_ms': 0.0,
        }
    
    @property
    def metadata(self) -> ComponentMetadata:
        """Get component metadata."""
        return ComponentMetadata(
            name=self._name,
            version="2.0.0",
            description="Pipeline processing engine",
            author="NetStealth Analyzer Team",
            priority=Priority.HIGH,
            tags=["pipeline", "orchestration", "async"],
            dependencies=[],
            supported_formats=[],
            configuration_schema={
                "type": "object",
                "properties": {
                    "max_concurrent_stages": {"type": "integer", "minimum": 1},
                    "default_timeout": {"type": "number", "minimum": 0},
                    "enable_parallel_execution": {"type": "boolean"},
                }
            }
        )
    
    @property
    def status(self) -> ComponentStatus:
        """Get current component status."""
        return self._status
    
    @property
    def pipeline_status(self) -> PipelineStatus:
        """Get current pipeline execution status."""
        if self._current_execution:
            return self._current_execution.status
        return PipelineStatus.IDLE
    
    @property
    def current_execution(self) -> Optional[PipelineExecution]:
        """Get current pipeline execution."""
        return self._current_execution
    
    async def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the pipeline engine."""
        if self._status != ComponentStatus.UNINITIALIZED:
            return
        
        self._status = ComponentStatus.INITIALIZING
        
        try:
            if config:
                self._max_concurrent_stages = config.get(
                    'max_concurrent_stages', self._max_concurrent_stages
                )
                self._default_timeout = config.get(
                    'default_timeout', self._default_timeout
                )
            
            # Initialize all registered stages
            for stage in self._stages.values():
                if hasattr(stage.component, 'initialize'):
                    await stage.component.initialize()
            
            self._status = ComponentStatus.READY
            logger.info(f"Pipeline engine '{self._name}' initialized with {len(self._stages)} stages")
            
        except Exception as e:
            self._status = ComponentStatus.ERROR
            await handle_error(e, ErrorContext(
                component="PipelineEngine",
                operation="initialize"
            ))
            raise
    
    async def shutdown(self) -> None:
        """Shutdown the pipeline engine."""
        if self._status == ComponentStatus.DISPOSED:
            return
        
        self._status = ComponentStatus.STOPPING
        
        try:
            # Cancel current execution if running
            if self._current_execution and self._current_execution.status == PipelineStatus.RUNNING:
                await self.cancel_execution()
            
            # Shutdown all stages
            for stage in self._stages.values():
                if hasattr(stage.component, 'shutdown'):
                    await stage.component.shutdown()
            
            self._status = ComponentStatus.DISPOSED
            logger.info(f"Pipeline engine '{self._name}' shutdown complete")
            
        except Exception as e:
            self._status = ComponentStatus.ERROR
            await handle_error(e, ErrorContext(
                component="PipelineEngine",
                operation="shutdown"
            ))
            raise
    
    def validate_configuration(self, config: Dict[str, Any]) -> bool:
        """Validate pipeline configuration."""
        try:
            max_concurrent = config.get('max_concurrent_stages', 1)
            if not isinstance(max_concurrent, int) or max_concurrent < 1:
                return False
            
            timeout = config.get('default_timeout', 0)
            if not isinstance(timeout, (int, float)) or timeout < 0:
                return False
            
            return True
            
        except Exception:
            return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get pipeline health status."""
        return {
            'status': self._status.value,
            'pipeline_status': self.pipeline_status.value,
            'total_stages': len(self._stages),
            'ready_stages': sum(1 for stage in self._stages.values() 
                              if stage.component.status == ComponentStatus.READY),
            'current_execution_id': str(self._current_execution.execution_id) 
                                  if self._current_execution else None,
            'stats': self._stats.copy(),
        }
    
    # ========================================================================
    # Stage Management
    # ========================================================================
    
    async def add_stage(self, stage: PipelineStage) -> None:
        """Add a stage to the pipeline."""
        if self._current_execution and self._current_execution.status == PipelineStatus.RUNNING:
            raise ValidationError("Cannot modify pipeline while execution is running")
        
        # Validate stage
        if not stage.name:
            raise ValidationError("Stage name cannot be empty")
        
        if stage.name in self._stages:
            raise ValidationError(f"Stage '{stage.name}' already exists")
        
        # Validate dependencies
        for dep in stage.depends_on:
            if dep not in self._stages and dep != stage.name:
                raise ValidationError(f"Dependency '{dep}' not found for stage '{stage.name}'")
        
        # Add stage
        self._stages[stage.name] = stage
        self._dependency_graph[stage.name] = set(stage.depends_on)
        
        # Rebuild stage order
        self._rebuild_stage_order()
        
        logger.debug(f"Added stage '{stage.name}' to pipeline")
        
        await self._event_bus.emit(
            AnalysisEvent.STAGE_STARTED,
            StageData(
                stage_name=stage.name,
                stage_type="configuration",
                source="PipelineEngine"
            )
        )
    
    async def remove_stage(self, stage_name: str) -> bool:
        """Remove a stage from the pipeline."""
        if self._current_execution and self._current_execution.status == PipelineStatus.RUNNING:
            raise ValidationError("Cannot modify pipeline while execution is running")
        
        if stage_name not in self._stages:
            return False
        
        # Check if other stages depend on this one
        dependents = [
            name for name, deps in self._dependency_graph.items()
            if stage_name in deps and name != stage_name
        ]
        
        if dependents:
            raise ValidationError(
                f"Cannot remove stage '{stage_name}': stages {dependents} depend on it"
            )
        
        # Remove stage
        del self._stages[stage_name]
        del self._dependency_graph[stage_name]
        
        # Rebuild stage order
        self._rebuild_stage_order()
        
        logger.debug(f"Removed stage '{stage_name}' from pipeline")
        return True
    
    def get_stage_order(self) -> List[str]:
        """Get the execution order of pipeline stages."""
        return self._stage_order.copy()
    
    def validate_pipeline(self) -> bool:
        """Validate that the pipeline configuration is correct."""
        try:
            # Check for circular dependencies
            if self._has_circular_dependencies():
                return False
            
            # Check that all dependencies exist
            for stage_name, deps in self._dependency_graph.items():
                for dep in deps:
                    if dep not in self._stages:
                        return False
            
            # Check that all stages are valid components
            for stage in self._stages.values():
                if not hasattr(stage.component, '__class__'):
                    return False
                
                # Check that component has required metadata attribute
                if not hasattr(stage.component, 'metadata'):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _rebuild_stage_order(self) -> None:
        """Rebuild stage execution order based on dependencies."""
        # Topological sort using Kahn's algorithm
        in_degree = {name: 0 for name in self._stages}
        
        # Calculate in-degrees (how many dependencies each stage has)
        for stage_name, deps in self._dependency_graph.items():
            in_degree[stage_name] = len(deps)
        
        # Find stages with no dependencies
        queue = [name for name, degree in in_degree.items() if degree == 0]
        result = []
        
        while queue:
            # Sort by priority for deterministic ordering (with fallback for components without metadata)
            def get_priority(name):
                component = self._stages[name].component
                if hasattr(component, 'metadata') and hasattr(component.metadata, 'priority'):
                    return component.metadata.priority.value
                return 50  # Default priority
            
            queue.sort(key=get_priority, reverse=True)
            current = queue.pop(0)
            result.append(current)
            
            # Update in-degrees of stages that depend on current stage
            for stage_name, deps in self._dependency_graph.items():
                if current in deps:
                    in_degree[stage_name] -= 1
                    if in_degree[stage_name] == 0:
                        queue.append(stage_name)
        
        if len(result) != len(self._stages):
            raise ValidationError("Circular dependency detected in pipeline stages")
        
        self._stage_order = result
    
    def _has_circular_dependencies(self) -> bool:
        """Check for circular dependencies in the pipeline."""
        visited = set()
        rec_stack = set()
        
        def has_cycle(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)
            
            for neighbor in self._dependency_graph.get(node, set()):
                if neighbor not in visited:
                    if has_cycle(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            
            rec_stack.remove(node)
            return False
        
        for stage_name in self._stages:
            if stage_name not in visited:
                if has_cycle(stage_name):
                    return True
        
        return False
    
    # ========================================================================
    # Pipeline Execution
    # ========================================================================
    
    async def execute(
        self,
        input_data: Any,
        context: ProcessingContext
    ) -> ProcessingResult[Dict[str, Any]]:
        """Execute the pipeline with input data."""
        if not self._stages:
            return ProcessingResult(
                success=False,
                error=ValidationError("No stages configured in pipeline")
            )
        
        if not self.validate_pipeline():
            return ProcessingResult(
                success=False,
                error=ValidationError("Pipeline configuration is invalid")
            )
        
        # Create execution context
        execution = PipelineExecution(
            status=PipelineStatus.INITIALIZING,
            context=context,
            stages={name: StageExecution(stage=stage) 
                   for name, stage in self._stages.items()}
        )
        
        self._current_execution = execution
        self._stats['total_executions'] += 1
        
        try:
            execution.status = PipelineStatus.RUNNING
            execution.start_time = datetime.now(timezone.utc)
            
            await self._event_bus.emit(
                AnalysisEvent.ANALYSIS_STARTED,
                StageData(
                    stage_name="pipeline",
                    stage_type="execution",
                    source="PipelineEngine"
                )
            )
            
            # Execute stages
            results = await self._execute_stages(input_data, execution)
            
            # Check if execution was cancelled
            if self._cancel_event.is_set():
                execution.status = PipelineStatus.CANCELLED
                self._stats['cancelled_executions'] += 1
                return ProcessingResult(
                    success=False,
                    error=NetStealthError("Pipeline execution was cancelled")
                )
            
            execution.status = PipelineStatus.COMPLETED
            execution.end_time = datetime.now(timezone.utc)
            execution.results = results
            
            self._stats['successful_executions'] += 1
            self._update_average_execution_time(execution.duration_ms or 0)
            
            await self._event_bus.emit(
                AnalysisEvent.ANALYSIS_COMPLETED,
                StageData(
                    stage_name="pipeline",
                    stage_type="execution",
                    duration_ms=execution.duration_ms,
                    items_processed=len(results),
                    source="PipelineEngine"
                )
            )
            
            return ProcessingResult(
                success=True,
                data=results,
                processing_time_ms=execution.duration_ms,
                items_processed=len(results)
            )
            
        except Exception as e:
            execution.status = PipelineStatus.FAILED
            execution.end_time = datetime.now(timezone.utc)
            execution.errors.append(e)
            
            self._stats['failed_executions'] += 1
            
            await self._event_bus.emit(
                AnalysisEvent.ANALYSIS_FAILED,
                ErrorData(
                    error_type=type(e).__name__,
                    message=str(e),
                    component="PipelineEngine",
                    source="PipelineEngine"
                )
            )
            
            return ProcessingResult(
                success=False,
                error=e,
                processing_time_ms=execution.duration_ms
            )
            
        finally:
            # Add to history
            self._execution_history.append(execution)
            if len(self._execution_history) > self._max_history:
                self._execution_history.pop(0)
            
            self._current_execution = None
            self._cancel_event.clear()
    
    async def execute_streaming(
        self,
        input_stream: AsyncIterator[Any],
        context: ProcessingContext
    ) -> AsyncIterator[Dict[str, Any]]:
        """Execute the pipeline with streaming input."""
        if not self._stages:
            raise ValidationError("No stages configured in pipeline")
        
        if not self.validate_pipeline():
            raise ValidationError("Pipeline configuration is invalid")
        
        # Create execution context
        execution = PipelineExecution(
            status=PipelineStatus.RUNNING,
            context=context,
            stages={name: StageExecution(stage=stage) 
                   for name, stage in self._stages.items()}
        )
        
        self._current_execution = execution
        execution.start_time = datetime.now(timezone.utc)
        
        try:
            await self._event_bus.emit(
                AnalysisEvent.ANALYSIS_STARTED,
                StageData(
                    stage_name="pipeline",
                    stage_type="streaming",
                    source="PipelineEngine"
                )
            )
            
            # Process input stream through pipeline stages
            async for item in input_stream:
                if self._cancel_event.is_set():
                    break
                
                await self._pause_event.wait()  # Respect pause
                
                # Execute stages for this item
                try:
                    result = await self._execute_stages(item, execution)
                    if result:
                        yield result
                        
                except Exception as e:
                    execution.errors.append(e)
                    await handle_error(e, ErrorContext(
                        component="PipelineEngine",
                        operation="streaming_execution"
                    ))
            
            execution.status = PipelineStatus.COMPLETED
            execution.end_time = datetime.now(timezone.utc)
            
        except Exception as e:
            execution.status = PipelineStatus.FAILED
            execution.end_time = datetime.now(timezone.utc)
            execution.errors.append(e)
            raise
            
        finally:
            self._execution_history.append(execution)
            if len(self._execution_history) > self._max_history:
                self._execution_history.pop(0)
            
            self._current_execution = None
            self._cancel_event.clear()
    
    async def _execute_stages(
        self,
        input_data: Any,
        execution: PipelineExecution
    ) -> Dict[str, Any]:
        """Execute all pipeline stages."""
        results = {'input': input_data}
        
        # Group stages by dependency level for parallel execution
        stage_levels = self._get_stage_levels()
        
        for level, stage_names in enumerate(stage_levels):
            if self._cancel_event.is_set():
                break
            
            await self._pause_event.wait()  # Respect pause
            
            # Execute stages at this level (potentially in parallel)
            level_results = await self._execute_stage_level(
                stage_names, results, execution
            )
            
            # Merge results
            results.update(level_results)
            
            # Update progress
            completed_stages = sum(1 for stage_exec in execution.stages.values() 
                                 if stage_exec.is_terminal)
            
            await emit_progress(
                current=completed_stages,
                total=len(execution.stages),
                stage=f"level_{level}",
                message=f"Completed {completed_stages}/{len(execution.stages)} stages",
                source="PipelineEngine"
            )
        
        return results
    
    async def _execute_stage_level(
        self,
        stage_names: List[str],
        input_results: Dict[str, Any],
        execution: PipelineExecution
    ) -> Dict[str, Any]:
        """Execute all stages at a given dependency level."""
        level_results = {}
        
        # Determine which stages can run in parallel
        parallel_stages = [name for name in stage_names 
                          if self._stages[name].parallel]
        sequential_stages = [name for name in stage_names 
                           if not self._stages[name].parallel]
        
        # Execute parallel stages concurrently
        if parallel_stages:
            async with TaskGroup() as tg:
                tasks = []
                for stage_name in parallel_stages:
                    task = tg.create_task(
                        self._execute_single_stage(stage_name, input_results, execution)
                    )
                    tasks.append((stage_name, task))
                
                # Collect results
                for stage_name, task in tasks:
                    try:
                        result = await task
                        if result is not None:
                            level_results[stage_name] = result
                    except Exception as e:
                        execution.stages[stage_name].error = e
                        execution.stages[stage_name].status = StageStatus.FAILED
        
        # Execute sequential stages one by one
        for stage_name in sequential_stages:
            if self._cancel_event.is_set():
                break
            
            try:
                result = await self._execute_single_stage(stage_name, input_results, execution)
                if result is not None:
                    level_results[stage_name] = result
                    # Sequential stages can use results from previous stages
                    input_results.update(level_results)
                    
            except Exception as e:
                execution.stages[stage_name].error = e
                execution.stages[stage_name].status = StageStatus.FAILED
                
                # Handle stage failure based on whether it's optional
                stage = self._stages[stage_name]
                if not stage.optional:
                    raise
        
        return level_results
    
    async def _execute_single_stage(
        self,
        stage_name: str,
        input_data: Dict[str, Any],
        execution: PipelineExecution
    ) -> Any:
        """Execute a single pipeline stage."""
        stage = self._stages[stage_name]
        stage_exec = execution.stages[stage_name]
        
        # Check if dependencies are met
        if not self._check_dependencies_met(stage_name, execution):
            stage_exec.status = StageStatus.SKIPPED
            return None
        
        stage_exec.status = StageStatus.RUNNING
        stage_exec.start_time = datetime.now(timezone.utc)
        
        await self._event_bus.emit(
            AnalysisEvent.STAGE_STARTED,
            StageData(
                stage_name=stage_name,
                stage_type=type(stage.component).__name__,
                source="PipelineEngine"
            )
        )
        
        try:
            # Set up timeout
            timeout = stage.timeout_seconds or self._default_timeout
            
            # Execute stage with timeout
            result = await asyncio.wait_for(
                self._call_stage_component(stage.component, input_data, execution.context),
                timeout=timeout
            )
            
            stage_exec.status = StageStatus.COMPLETED
            stage_exec.result = result
            stage_exec.end_time = datetime.now(timezone.utc)
            
            self._stats['total_stages_executed'] += 1
            
            await self._event_bus.emit(
                AnalysisEvent.STAGE_COMPLETED,
                StageData(
                    stage_name=stage_name,
                    stage_type=type(stage.component).__name__,
                    duration_ms=stage_exec.duration_ms,
                    success_count=1,
                    source="PipelineEngine"
                )
            )
            
            return result.data if isinstance(result, ProcessingResult) else result
            
        except asyncio.TimeoutError:
            stage_exec.status = StageStatus.FAILED
            stage_exec.end_time = datetime.now(timezone.utc)
            error = TimeoutError(f"stage_{stage_name}", timeout)
            stage_exec.error = error
            
            await self._event_bus.emit(
                AnalysisEvent.STAGE_FAILED,
                ErrorData(
                    error_type="TimeoutError",
                    message=str(error),
                    component=stage_name,
                    source="PipelineEngine"
                )
            )
            
            # Retry if configured
            if stage_exec.retry_count < stage.retry_count:
                stage_exec.retry_count += 1
                logger.info(f"Retrying stage '{stage_name}' (attempt {stage_exec.retry_count})")
                return await self._execute_single_stage(stage_name, input_data, execution)
            
            if not stage.optional:
                raise error
            
            return None
            
        except Exception as e:
            stage_exec.status = StageStatus.FAILED
            stage_exec.end_time = datetime.now(timezone.utc)
            stage_exec.error = e
            
            await self._event_bus.emit(
                AnalysisEvent.STAGE_FAILED,
                ErrorData(
                    error_type=type(e).__name__,
                    message=str(e),
                    component=stage_name,
                    source="PipelineEngine"
                )
            )
            
            # Retry if configured
            if stage_exec.retry_count < stage.retry_count:
                stage_exec.retry_count += 1
                logger.info(f"Retrying stage '{stage_name}' (attempt {stage_exec.retry_count})")
                return await self._execute_single_stage(stage_name, input_data, execution)
            
            if not stage.optional:
                raise
            
            return None
    
    async def _call_stage_component(
        self,
        component: IComponent,
        input_data: Dict[str, Any],
        context: Optional[ProcessingContext]
    ) -> Any:
        """Call a stage component with appropriate method."""
        # Try different component interfaces
        if hasattr(component, 'parse') and callable(component.parse):
            # Parser component - call with file path and context
            file_path = context.file_path if context else None
            if file_path and context:
                return await component.parse(file_path, context)
            elif file_path:
                return await component.parse(file_path)
        
        elif hasattr(component, 'detect') and callable(component.detect):
            # Detector component - extract log entries and call with context
            log_entries = []
            
            # Extract log entries from input data
            if 'log_entries' in input_data:
                log_entries = input_data['log_entries']
            elif isinstance(input_data, list):
                log_entries = input_data
            else:
                # Look for log entries in nested data
                for key, value in input_data.items():
                    if key == 'log_entries' and isinstance(value, list):
                        log_entries = value
                        break
                    elif isinstance(value, dict) and 'log_entries' in value:
                        log_entries = value['log_entries']
                        break
            
            if context:
                return await component.detect(log_entries, context)
            else:
                # Fallback to DetectionContext for backward compatibility
                from ..detectors.base import DetectionContext
                detection_context = DetectionContext(
                    network_traces=[],
                    service_domains=[],
                    confidence_threshold=0.7
                )
                return await component.detect(detection_context)
        
        elif hasattr(component, 'generate_report') and callable(component.generate_report):
            # Reporter component
            from .interfaces import ReportConfig, ReportFormat
            config = ReportConfig(format=ReportFormat.JSON)
            return await component.generate_report(input_data, config, context)
        
        elif hasattr(component, 'process') and callable(component.process):
            # Generic processor
            return await component.process(input_data, context)
        
        else:
            raise ValidationError(f"Component {type(component).__name__} has no supported interface")
    
    def _check_dependencies_met(
        self,
        stage_name: str,
        execution: PipelineExecution
    ) -> bool:
        """Check if all dependencies for a stage are met."""
        dependencies = self._dependency_graph.get(stage_name, set())
        
        for dep in dependencies:
            dep_exec = execution.stages.get(dep)
            if not dep_exec or dep_exec.status != StageStatus.COMPLETED:
                return False
        
        return True
    
    def _get_stage_levels(self) -> List[List[str]]:
        """Group stages by dependency level for parallel execution."""
        levels = []
        remaining_stages = set(self._stage_order)
        
        while remaining_stages:
            current_level = []
            
            for stage_name in list(remaining_stages):
                dependencies = self._dependency_graph.get(stage_name, set())
                
                # Check if all dependencies are in previous levels
                if all(dep not in remaining_stages for dep in dependencies):
                    current_level.append(stage_name)
            
            if not current_level:
                # This shouldn't happen if pipeline is valid
                raise ValidationError("Circular dependency or invalid pipeline configuration")
            
            levels.append(current_level)
            remaining_stages -= set(current_level)
        
        return levels
    
    def _update_average_execution_time(self, duration_ms: int) -> None:
        """Update average execution time statistics."""
        current_avg = self._stats['average_execution_time_ms']
        total_executions = self._stats['successful_executions']
        
        if total_executions == 1:
            self._stats['average_execution_time_ms'] = float(duration_ms)
        else:
            # Calculate running average
            self._stats['average_execution_time_ms'] = (
                (current_avg * (total_executions - 1) + duration_ms) / total_executions
            )
    
    # ========================================================================
    # Pipeline Control
    # ========================================================================
    
    async def pause_execution(self) -> None:
        """Pause pipeline execution."""
        if self._current_execution and self._current_execution.status == PipelineStatus.RUNNING:
            self._current_execution.status = PipelineStatus.PAUSED
            self._pause_event.clear()
            logger.info("Pipeline execution paused")
    
    async def resume_execution(self) -> None:
        """Resume paused pipeline execution."""
        if self._current_execution and self._current_execution.status == PipelineStatus.PAUSED:
            self._current_execution.status = PipelineStatus.RUNNING
            self._pause_event.set()
            logger.info("Pipeline execution resumed")
    
    async def cancel_execution(self) -> None:
        """Cancel current pipeline execution."""
        if self._current_execution and self._current_execution.status in {
            PipelineStatus.RUNNING, PipelineStatus.PAUSED
        }:
            self._current_execution.status = PipelineStatus.STOPPING
            self._cancel_event.set()
            logger.info("Pipeline execution cancellation requested")
    
    # ========================================================================
    # Statistics and Monitoring
    # ========================================================================
    
    def get_execution_history(self, limit: Optional[int] = None) -> List[PipelineExecution]:
        """Get pipeline execution history."""
        history = self._execution_history
        if limit:
            history = history[-limit:]
        return history.copy()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive pipeline statistics."""
        return {
            'pipeline_stats': self._stats.copy(),
            'current_execution': {
                'execution_id': str(self._current_execution.execution_id) if self._current_execution else None,
                'status': self.pipeline_status.value,
                'completed_stages': self._current_execution.completed_stages if self._current_execution else 0,
                'failed_stages': self._current_execution.failed_stages if self._current_execution else 0,
                'total_stages': self._current_execution.total_stages if self._current_execution else 0,
                'duration_ms': self._current_execution.duration_ms if self._current_execution else None,
            },
            'stage_stats': {
                name: {
                    'component_type': type(stage.component).__name__,
                    'priority': stage.component.metadata.priority.value,
                    'parallel': stage.parallel,
                    'optional': stage.optional,
                    'dependencies': stage.depends_on,
                }
                for name, stage in self._stages.items()
            }
        }
    
    def clear_history(self) -> None:
        """Clear execution history."""
        self._execution_history.clear()
        logger.debug("Pipeline execution history cleared")


# Export public API
__all__ = [
    # Core classes
    'PipelineEngine',
    'PipelineExecution',
    'StageExecution',
    
    # Enums
    'PipelineStatus',
    'StageStatus',
]
