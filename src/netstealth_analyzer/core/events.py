"""
Event-driven system for NetStealth Analyzer.

This module provides a comprehensive event bus system for real-time progress tracking,
issue notifications, and inter-component communication throughout the analysis pipeline.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import asyncio
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Union, TypeVar, Generic
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4, UUID
from weakref import WeakSet
import logging
from contextlib import asynccontextmanager

from ..compatibility import TaskGroup, ensure_async, override

# Type variables
T = TypeVar('T')
EventHandler = Callable[['AnalysisEvent', Any], Union[None, asyncio.Task]]
AsyncEventHandler = Callable[['AnalysisEvent', Any], asyncio.Task]

logger = logging.getLogger(__name__)


class AnalysisEvent(Enum):
    """
    Enumeration of all analysis events that can be emitted during processing.
    
    Events are organized by lifecycle stage and component for better organization.
    """
    
    # === Analysis Lifecycle Events ===
    ANALYSIS_STARTED = auto()           # Analysis pipeline started
    ANALYSIS_COMPLETED = auto()         # Analysis pipeline completed successfully
    ANALYSIS_FAILED = auto()            # Analysis pipeline failed with error
    ANALYSIS_CANCELLED = auto()         # Analysis pipeline was cancelled
    
    # === Progress Events ===
    PROGRESS_UPDATE = auto()            # General progress update (percentage)
    STAGE_STARTED = auto()              # Analysis stage started (parsing, detection, etc.)
    STAGE_COMPLETED = auto()            # Analysis stage completed
    STAGE_FAILED = auto()               # Analysis stage failed
    
    # === Parsing Events ===
    PARSER_STARTED = auto()             # Log parser started processing
    PARSER_COMPLETED = auto()           # Log parser completed processing
    PARSER_FAILED = auto()              # Log parser failed
    LOG_ENTRY_PARSED = auto()           # Individual log entry parsed
    
    # === Detection Events ===
    DETECTOR_STARTED = auto()           # Detector started analysis
    DETECTOR_COMPLETED = auto()         # Detector completed analysis
    DETECTOR_FAILED = auto()            # Detector failed
    ISSUE_FOUND = auto()                # Security issue discovered
    ISSUE_RESOLVED = auto()             # Issue marked as resolved/false positive
    
    # === Reporting Events ===
    REPORT_STARTED = auto()             # Report generation started
    REPORT_COMPLETED = auto()           # Report generation completed
    REPORT_CHUNK_READY = auto()         # Report chunk available for streaming
    
    # === Plugin Events ===
    PLUGIN_LOADED = auto()              # Plugin successfully loaded
    PLUGIN_FAILED = auto()              # Plugin failed to load or execute
    PLUGIN_STARTED = auto()             # Plugin started execution
    PLUGIN_COMPLETED = auto()           # Plugin completed execution
    PLUGIN_EXECUTED = auto()            # Plugin execution completed (alias for PLUGIN_COMPLETED)
    
    # === Configuration Events ===
    CONFIGURATION_CHANGED = auto()      # Configuration was modified
    CONFIGURATION_LOADED = auto()       # Configuration loaded successfully
    CONFIGURATION_VALIDATED = auto()    # Configuration validation completed
    
    # === System Events ===
    WARNING_ISSUED = auto()             # Non-fatal warning issued
    ERROR_OCCURRED = auto()             # Error occurred (with recovery)
    RESOURCE_USAGE = auto()             # Resource usage statistics
    DEBUG_INFO = auto()                 # Debug information


@dataclass(frozen=True)
class EventData:
    """
    Base class for event data payloads.
    
    All event data should inherit from this class to ensure consistent
    metadata and traceability across the event system.
    """
    
    event_id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: Optional[str] = None
    correlation_id: Optional[UUID] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def with_correlation(self, correlation_id: UUID) -> 'EventData':
        """Create a copy with correlation ID set."""
        return self.__class__(
            event_id=self.event_id,
            timestamp=self.timestamp,
            source=self.source,
            correlation_id=correlation_id,
            metadata=self.metadata
        )


@dataclass(frozen=True)
class ProgressData(EventData):
    """Event data for progress updates."""
    
    current: int = 0
    total: int = 0
    stage: str = ""
    message: Optional[str] = None
    
    @property
    def percentage(self) -> float:
        """Calculate completion percentage."""
        if self.total == 0:
            return 100.0
        return min(100.0, (self.current / self.total) * 100.0)


@dataclass(frozen=True)
class IssueData(EventData):
    """Event data for security issues."""
    
    issue_id: str = ""
    title: str = ""
    severity: str = ""
    category: str = ""
    description: str = ""
    confidence: float = 0.0
    affected_urls: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ErrorData(EventData):
    """Event data for errors and exceptions."""
    
    error_type: str = ""
    message: str = ""
    component: str = ""
    recoverable: bool = True
    stack_trace: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StageData(EventData):
    """Event data for analysis stages."""
    
    stage_name: str = ""
    stage_type: str = ""  # 'parsing', 'detection', 'reporting', etc.
    duration_ms: Optional[int] = None
    items_processed: Optional[int] = None
    success_count: Optional[int] = None
    error_count: Optional[int] = None


class EventSubscription:
    """
    Represents a subscription to specific events.
    
    Manages the lifecycle of event handlers and provides filtering capabilities.
    """
    
    def __init__(
        self,
        handler: EventHandler,
        events: Union[AnalysisEvent, List[AnalysisEvent]],
        subscription_id: Optional[UUID] = None,
        filter_func: Optional[Callable[[AnalysisEvent, Any], bool]] = None,
        once: bool = False
    ):
        self.subscription_id = subscription_id or uuid4()
        self.handler = ensure_async(handler)
        self.events = [events] if isinstance(events, AnalysisEvent) else events
        self.filter_func = filter_func
        self.once = once
        self.call_count = 0
        self.created_at = datetime.now(timezone.utc)
        self.last_called_at: Optional[datetime] = None
        self.is_active = True
    
    def matches(self, event: AnalysisEvent, data: Any) -> bool:
        """Check if this subscription matches the given event."""
        if not self.is_active:
            return False
        
        if event not in self.events:
            return False
        
        if self.filter_func and not self.filter_func(event, data):
            return False
        
        return True
    
    async def handle(self, event: AnalysisEvent, data: Any) -> None:
        """Handle the event with this subscription."""
        if not self.is_active:
            return
        
        self.call_count += 1
        self.last_called_at = datetime.now(timezone.utc)
        
        try:
            await self.handler(event, data)
            
            if self.once:
                self.is_active = False
                
        except Exception as e:
            logger.error(
                f"Error in event handler {self.subscription_id}: {e}",
                exc_info=True
            )
            # Re-raise to let the EventBus handle the error counting
            raise
    
    def unsubscribe(self) -> None:
        """Deactivate this subscription."""
        self.is_active = False


class EventBus:
    """
    Central event bus for the NetStealth Analyzer.
    
    Provides async event emission, subscription management, and event filtering.
    Supports both fire-and-forget and awaitable event handling patterns.
    """
    
    def __init__(self, max_concurrent_handlers: int = 50):
        self._subscriptions: List[EventSubscription] = []
        self._event_history: List[tuple[AnalysisEvent, Any, datetime]] = []
        self._max_history = 1000
        self._max_concurrent_handlers = max_concurrent_handlers
        self._active_handlers: WeakSet = WeakSet()
        self._stats = {
            'events_emitted': 0,
            'handlers_executed': 0,
            'handler_errors': 0,
        }
        self._lock = asyncio.Lock()
    
    def subscribe(
        self,
        events: Union[AnalysisEvent, List[AnalysisEvent]],
        handler: EventHandler,
        filter_func: Optional[Callable[[AnalysisEvent, Any], bool]] = None,
        once: bool = False
    ) -> EventSubscription:
        """
        Subscribe to one or more events.
        
        Args:
            events: Event(s) to subscribe to
            handler: Function to call when event occurs
            filter_func: Optional filter function for event data
            once: If True, unsubscribe after first event
            
        Returns:
            EventSubscription object for managing the subscription
        """
        subscription = EventSubscription(
            handler=handler,
            events=events,
            filter_func=filter_func,
            once=once
        )
        
        self._subscriptions.append(subscription)
        
        logger.debug(
            f"Subscribed to events {events} with handler {getattr(handler, '__name__', 'anonymous')}"
        )
        
        return subscription
    
    def unsubscribe(self, subscription: EventSubscription) -> bool:
        """
        Unsubscribe from events.
        
        Args:
            subscription: Subscription to remove
            
        Returns:
            True if subscription was found and removed
        """
        try:
            subscription.unsubscribe()
            self._subscriptions.remove(subscription)
            logger.debug(f"Unsubscribed {subscription.subscription_id}")
            return True
        except ValueError:
            return False
    
    def unsubscribe_all(self, handler: Optional[EventHandler] = None) -> int:
        """
        Unsubscribe all subscriptions, optionally filtered by handler.
        
        Args:
            handler: If provided, only unsubscribe this handler
            
        Returns:
            Number of subscriptions removed
        """
        removed = 0
        subscriptions_to_remove = []
        
        for subscription in self._subscriptions:
            # Compare the original handler, not the wrapped async version
            original_handler = getattr(subscription.handler, '__wrapped__', subscription.handler)
            if handler is None or original_handler == handler or subscription.handler == handler:
                subscription.unsubscribe()
                subscriptions_to_remove.append(subscription)
                removed += 1
        
        for subscription in subscriptions_to_remove:
            self._subscriptions.remove(subscription)
        
        logger.debug(f"Unsubscribed {removed} subscriptions")
        return removed
    
    async def emit(
        self,
        event: AnalysisEvent,
        data: Any = None,
        wait_for_handlers: bool = False
    ) -> None:
        """
        Emit an event to all subscribers.
        
        Args:
            event: Event to emit
            data: Event data payload
            wait_for_handlers: If True, wait for all handlers to complete
        """
        async with self._lock:
            self._stats['events_emitted'] += 1
            
            # Add to history
            self._event_history.append((event, data, datetime.now(timezone.utc)))
            while len(self._event_history) > self._max_history:
                self._event_history.pop(0)
        
        # Find matching subscriptions
        matching_subscriptions = [
            sub for sub in self._subscriptions
            if sub.matches(event, data)
        ]
        
        if not matching_subscriptions:
            logger.debug(f"No subscribers for event {event}")
            return
        
        logger.debug(
            f"Emitting {event} to {len(matching_subscriptions)} subscribers"
        )
        
        # Execute handlers
        if wait_for_handlers:
            await self._execute_handlers_sync(matching_subscriptions, event, data)
        else:
            await self._execute_handlers_async(matching_subscriptions, event, data)
    
    async def _execute_handlers_sync(
        self,
        subscriptions: List[EventSubscription],
        event: AnalysisEvent,
        data: Any
    ) -> None:
        """Execute handlers synchronously (wait for all to complete)."""
        async with TaskGroup() as tg:
            for subscription in subscriptions:
                tg.create_task(self._handle_subscription(subscription, event, data))
    
    async def _execute_handlers_async(
        self,
        subscriptions: List[EventSubscription],
        event: AnalysisEvent,
        data: Any
    ) -> None:
        """Execute handlers asynchronously (fire and forget)."""
        # Limit concurrent handlers to prevent resource exhaustion
        semaphore = asyncio.Semaphore(self._max_concurrent_handlers)
        
        tasks = []
        for subscription in subscriptions:
            task = asyncio.create_task(
                self._handle_subscription_with_semaphore(
                    semaphore, subscription, event, data
                )
            )
            tasks.append(task)
            self._active_handlers.add(task)
        
        # Don't wait for completion in async mode
        # Tasks will complete in background
    
    async def _handle_subscription_with_semaphore(
        self,
        semaphore: asyncio.Semaphore,
        subscription: EventSubscription,
        event: AnalysisEvent,
        data: Any
    ) -> None:
        """Handle subscription with semaphore for concurrency control."""
        async with semaphore:
            await self._handle_subscription(subscription, event, data)
    
    async def _handle_subscription(
        self,
        subscription: EventSubscription,
        event: AnalysisEvent,
        data: Any
    ) -> None:
        """Handle a single subscription."""
        try:
            await subscription.handle(event, data)
            self._stats['handlers_executed'] += 1
        except Exception as e:
            self._stats['handler_errors'] += 1
            logger.error(
                f"Handler error for {event}: {e}",
                exc_info=True
            )
    
    def get_event_history(
        self,
        event_filter: Optional[AnalysisEvent] = None,
        limit: Optional[int] = None
    ) -> List[tuple[AnalysisEvent, Any, datetime]]:
        """
        Get event history, optionally filtered.
        
        Args:
            event_filter: Only return events of this type
            limit: Maximum number of events to return
            
        Returns:
            List of (event, data, timestamp) tuples
        """
        history = self._event_history
        
        if event_filter:
            history = [
                (event, data, timestamp)
                for event, data, timestamp in history
                if event == event_filter
            ]
        
        if limit:
            history = history[-limit:]
        
        return history
    
    def get_stats(self) -> Dict[str, Any]:
        """Get event bus statistics."""
        return {
            **self._stats,
            'active_subscriptions': len([s for s in self._subscriptions if s.is_active]),
            'total_subscriptions': len(self._subscriptions),
            'active_handlers': len(self._active_handlers),
            'history_size': len(self._event_history),
        }
    
    async def wait_for_handlers(self, timeout: Optional[float] = None) -> None:
        """
        Wait for all active handlers to complete.
        
        Args:
            timeout: Maximum time to wait in seconds
        """
        if not self._active_handlers:
            return
        
        try:
            await asyncio.wait_for(
                asyncio.gather(*list(self._active_handlers), return_exceptions=True),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"Timeout waiting for event handlers after {timeout}s")
    
    @asynccontextmanager
    async def temporary_subscription(
        self,
        events: Union[AnalysisEvent, List[AnalysisEvent]],
        handler: EventHandler,
        filter_func: Optional[Callable[[AnalysisEvent, Any], bool]] = None
    ):
        """
        Context manager for temporary event subscriptions.
        
        Automatically unsubscribes when exiting the context.
        """
        subscription = self.subscribe(events, handler, filter_func)
        try:
            yield subscription
        finally:
            self.unsubscribe(subscription)
    
    def clear_history(self) -> None:
        """Clear event history."""
        self._event_history.clear()
        logger.debug("Event history cleared")
    
    async def shutdown(self) -> None:
        """
        Shutdown the event bus gracefully.
        
        Waits for active handlers and cleans up resources.
        """
        logger.info("Shutting down event bus...")
        
        # Wait for active handlers with timeout
        await self.wait_for_handlers(timeout=5.0)
        
        # Unsubscribe all
        self.unsubscribe_all()
        
        # Clear history
        self.clear_history()
        
        logger.info("Event bus shutdown complete")


# Global event bus instance
_global_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """
    Get the global event bus instance.
    
    Creates one if it doesn't exist.
    """
    global _global_event_bus
    if _global_event_bus is None:
        _global_event_bus = EventBus()
    return _global_event_bus


def set_event_bus(event_bus: EventBus) -> None:
    """Set the global event bus instance."""
    global _global_event_bus
    _global_event_bus = event_bus


# Convenience functions for common event patterns
async def emit_progress(
    current: int,
    total: int,
    stage: str,
    message: Optional[str] = None,
    source: Optional[str] = None
) -> None:
    """Emit a progress update event."""
    data = ProgressData(
        current=current,
        total=total,
        stage=stage,
        message=message,
        source=source
    )
    await get_event_bus().emit(AnalysisEvent.PROGRESS_UPDATE, data)


async def emit_issue_found(
    issue_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    confidence: float,
    affected_urls: Optional[List[str]] = None,
    evidence: Optional[Dict[str, Any]] = None,
    source: Optional[str] = None
) -> None:
    """Emit an issue found event."""
    data = IssueData(
        issue_id=issue_id,
        title=title,
        severity=severity,
        category=category,
        description=description,
        confidence=confidence,
        affected_urls=affected_urls or [],
        evidence=evidence or {},
        source=source
    )
    await get_event_bus().emit(AnalysisEvent.ISSUE_FOUND, data)


async def emit_error(
    error_type: str,
    message: str,
    component: str,
    recoverable: bool = True,
    stack_trace: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
    source: Optional[str] = None
) -> None:
    """Emit an error event."""
    data = ErrorData(
        error_type=error_type,
        message=message,
        component=component,
        recoverable=recoverable,
        stack_trace=stack_trace,
        context=context or {},
        source=source
    )
    await get_event_bus().emit(AnalysisEvent.ERROR_OCCURRED, data)


# Export public API
__all__ = [
    # Core classes
    'EventBus',
    'EventSubscription',
    
    # Event types
    'AnalysisEvent',
    
    # Data classes
    'EventData',
    'ProgressData',
    'IssueData',
    'ErrorData',
    'StageData',
    
    # Global functions
    'get_event_bus',
    'set_event_bus',
    
    # Convenience functions
    'emit_progress',
    'emit_issue_found',
    'emit_error',
    
    # Type hints
    'EventHandler',
    'AsyncEventHandler',
]
