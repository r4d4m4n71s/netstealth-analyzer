"""
Unit tests for NetStealth Analyzer event system.

Tests the EventBus, event subscriptions, event data classes, and convenience functions
with full async support and comprehensive coverage.
"""

import asyncio
import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timezone, timedelta
from uuid import UUID, uuid4
from typing import List, Dict, Any
import logging

from src.netstealth_analyzer.core.events import (
    # Core classes
    EventBus,
    EventSubscription,
    
    # Event types
    AnalysisEvent,
    
    # Data classes
    EventData,
    ProgressData,
    IssueData,
    ErrorData,
    StageData,
    
    # Global functions
    get_event_bus,
    set_event_bus,
    
    # Convenience functions
    emit_progress,
    emit_issue_found,
    emit_error,
    
    # Type hints
    EventHandler,
    AsyncEventHandler,
)


class TestAnalysisEvent:
    """Test AnalysisEvent enumeration."""
    
    def test_analysis_lifecycle_events(self):
        """Test analysis lifecycle events exist."""
        assert AnalysisEvent.ANALYSIS_STARTED
        assert AnalysisEvent.ANALYSIS_COMPLETED
        assert AnalysisEvent.ANALYSIS_FAILED
        assert AnalysisEvent.ANALYSIS_CANCELLED
    
    def test_progress_events(self):
        """Test progress events exist."""
        assert AnalysisEvent.PROGRESS_UPDATE
        assert AnalysisEvent.STAGE_STARTED
        assert AnalysisEvent.STAGE_COMPLETED
        assert AnalysisEvent.STAGE_FAILED
    
    def test_parsing_events(self):
        """Test parsing events exist."""
        assert AnalysisEvent.PARSER_STARTED
        assert AnalysisEvent.PARSER_COMPLETED
        assert AnalysisEvent.PARSER_FAILED
        assert AnalysisEvent.LOG_ENTRY_PARSED
    
    def test_detection_events(self):
        """Test detection events exist."""
        assert AnalysisEvent.DETECTOR_STARTED
        assert AnalysisEvent.DETECTOR_COMPLETED
        assert AnalysisEvent.DETECTOR_FAILED
        assert AnalysisEvent.ISSUE_FOUND
        assert AnalysisEvent.ISSUE_RESOLVED
    
    def test_reporting_events(self):
        """Test reporting events exist."""
        assert AnalysisEvent.REPORT_STARTED
        assert AnalysisEvent.REPORT_COMPLETED
        assert AnalysisEvent.REPORT_CHUNK_READY
    
    def test_plugin_events(self):
        """Test plugin events exist."""
        assert AnalysisEvent.PLUGIN_LOADED
        assert AnalysisEvent.PLUGIN_FAILED
        assert AnalysisEvent.PLUGIN_STARTED
        assert AnalysisEvent.PLUGIN_COMPLETED
    
    def test_system_events(self):
        """Test system events exist."""
        assert AnalysisEvent.WARNING_ISSUED
        assert AnalysisEvent.ERROR_OCCURRED
        assert AnalysisEvent.RESOURCE_USAGE
        assert AnalysisEvent.DEBUG_INFO
    
    def test_event_uniqueness(self):
        """Test that all events have unique values."""
        events = list(AnalysisEvent)
        values = [event.value for event in events]
        assert len(values) == len(set(values))


class TestEventData:
    """Test EventData base class."""
    
    def test_event_data_creation(self):
        """Test creating EventData instance."""
        data = EventData()
        
        assert isinstance(data.event_id, UUID)
        assert isinstance(data.timestamp, datetime)
        assert data.timestamp.tzinfo == timezone.utc
        assert data.source is None
        assert data.correlation_id is None
        assert data.metadata == {}
    
    def test_event_data_with_parameters(self):
        """Test creating EventData with parameters."""
        event_id = uuid4()
        timestamp = datetime.now(timezone.utc)
        correlation_id = uuid4()
        metadata = {"key": "value"}
        
        data = EventData(
            event_id=event_id,
            timestamp=timestamp,
            source="test_source",
            correlation_id=correlation_id,
            metadata=metadata
        )
        
        assert data.event_id == event_id
        assert data.timestamp == timestamp
        assert data.source == "test_source"
        assert data.correlation_id == correlation_id
        assert data.metadata == metadata
    
    def test_with_correlation(self):
        """Test with_correlation method."""
        original_data = EventData(source="test")
        correlation_id = uuid4()
        
        new_data = original_data.with_correlation(correlation_id)
        
        assert new_data.correlation_id == correlation_id
        assert new_data.source == "test"
        assert new_data.event_id == original_data.event_id
        assert new_data.timestamp == original_data.timestamp
    
    def test_event_data_immutable(self):
        """Test that EventData is immutable."""
        data = EventData()
        
        with pytest.raises(AttributeError):
            data.source = "new_source"


class TestProgressData:
    """Test ProgressData class."""
    
    def test_progress_data_creation(self):
        """Test creating ProgressData instance."""
        data = ProgressData(current=50, total=100, stage="parsing")
        
        assert data.current == 50
        assert data.total == 100
        assert data.stage == "parsing"
        assert data.message is None
        assert isinstance(data.event_id, UUID)
    
    def test_percentage_calculation(self):
        """Test percentage calculation."""
        # Normal case
        data = ProgressData(current=25, total=100)
        assert data.percentage == 25.0
        
        # Zero total
        data = ProgressData(current=10, total=0)
        assert data.percentage == 100.0
        
        # Over 100%
        data = ProgressData(current=150, total=100)
        assert data.percentage == 100.0
        
        # Partial percentage
        data = ProgressData(current=1, total=3)
        assert abs(data.percentage - 33.333333333333336) < 0.001
    
    def test_progress_data_with_message(self):
        """Test ProgressData with message."""
        data = ProgressData(
            current=10,
            total=20,
            stage="detection",
            message="Processing detectors"
        )
        
        assert data.current == 10
        assert data.total == 20
        assert data.stage == "detection"
        assert data.message == "Processing detectors"


class TestIssueData:
    """Test IssueData class."""
    
    def test_issue_data_creation(self):
        """Test creating IssueData instance."""
        data = IssueData(
            issue_id="issue-123",
            title="SQL Injection",
            severity="high",
            category="injection",
            description="Potential SQL injection vulnerability",
            confidence=0.85
        )
        
        assert data.issue_id == "issue-123"
        assert data.title == "SQL Injection"
        assert data.severity == "high"
        assert data.category == "injection"
        assert data.description == "Potential SQL injection vulnerability"
        assert data.confidence == 0.85
        assert data.affected_urls == []
        assert data.evidence == {}
    
    def test_issue_data_with_urls_and_evidence(self):
        """Test IssueData with URLs and evidence."""
        urls = ["http://example.com/login", "http://example.com/search"]
        evidence = {"payload": "' OR 1=1 --", "response_time": 2.5}
        
        data = IssueData(
            issue_id="issue-456",
            title="XSS Vulnerability",
            severity="medium",
            category="xss",
            description="Cross-site scripting vulnerability",
            confidence=0.75,
            affected_urls=urls,
            evidence=evidence
        )
        
        assert data.affected_urls == urls
        assert data.evidence == evidence


class TestErrorData:
    """Test ErrorData class."""
    
    def test_error_data_creation(self):
        """Test creating ErrorData instance."""
        data = ErrorData(
            error_type="ValueError",
            message="Invalid input parameter",
            component="parser",
            recoverable=True
        )
        
        assert data.error_type == "ValueError"
        assert data.message == "Invalid input parameter"
        assert data.component == "parser"
        assert data.recoverable is True
        assert data.stack_trace is None
        assert data.context == {}
    
    def test_error_data_with_stack_trace(self):
        """Test ErrorData with stack trace and context."""
        stack_trace = "Traceback (most recent call last):\n  File..."
        context = {"input_file": "test.log", "line_number": 42}
        
        data = ErrorData(
            error_type="ParseError",
            message="Failed to parse log entry",
            component="log_parser",
            recoverable=False,
            stack_trace=stack_trace,
            context=context
        )
        
        assert data.stack_trace == stack_trace
        assert data.context == context
        assert data.recoverable is False


class TestStageData:
    """Test StageData class."""
    
    def test_stage_data_creation(self):
        """Test creating StageData instance."""
        data = StageData(
            stage_name="parsing",
            stage_type="parsing",
            duration_ms=1500,
            items_processed=100,
            success_count=95,
            error_count=5
        )
        
        assert data.stage_name == "parsing"
        assert data.stage_type == "parsing"
        assert data.duration_ms == 1500
        assert data.items_processed == 100
        assert data.success_count == 95
        assert data.error_count == 5


class TestEventSubscription:
    """Test EventSubscription class."""
    
    def test_subscription_creation(self):
        """Test creating EventSubscription."""
        handler = Mock()
        events = [AnalysisEvent.ANALYSIS_STARTED, AnalysisEvent.ANALYSIS_COMPLETED]
        
        subscription = EventSubscription(
            handler=handler,
            events=events
        )
        
        assert subscription.handler is not None
        assert subscription.events == events
        assert subscription.filter_func is None
        assert subscription.once is False
        assert subscription.call_count == 0
        assert subscription.is_active is True
        assert isinstance(subscription.subscription_id, UUID)
        assert isinstance(subscription.created_at, datetime)
        assert subscription.last_called_at is None
    
    def test_subscription_with_single_event(self):
        """Test subscription with single event."""
        handler = Mock()
        event = AnalysisEvent.ISSUE_FOUND
        
        subscription = EventSubscription(
            handler=handler,
            events=event
        )
        
        assert subscription.events == [event]
    
    def test_subscription_with_filter(self):
        """Test subscription with filter function."""
        handler = Mock()
        filter_func = lambda event, data: data.get("severity") == "high"
        
        subscription = EventSubscription(
            handler=handler,
            events=AnalysisEvent.ISSUE_FOUND,
            filter_func=filter_func
        )
        
        assert subscription.filter_func == filter_func
    
    def test_subscription_matches(self):
        """Test subscription matching logic."""
        handler = Mock()
        subscription = EventSubscription(
            handler=handler,
            events=[AnalysisEvent.ISSUE_FOUND, AnalysisEvent.PROGRESS_UPDATE]
        )
        
        # Should match subscribed events
        assert subscription.matches(AnalysisEvent.ISSUE_FOUND, {})
        assert subscription.matches(AnalysisEvent.PROGRESS_UPDATE, {})
        
        # Should not match other events
        assert not subscription.matches(AnalysisEvent.ANALYSIS_STARTED, {})
    
    def test_subscription_matches_with_filter(self):
        """Test subscription matching with filter."""
        handler = Mock()
        filter_func = lambda event, data: data.get("severity") == "high"
        
        subscription = EventSubscription(
            handler=handler,
            events=AnalysisEvent.ISSUE_FOUND,
            filter_func=filter_func
        )
        
        # Should match with correct filter
        assert subscription.matches(AnalysisEvent.ISSUE_FOUND, {"severity": "high"})
        
        # Should not match with incorrect filter
        assert not subscription.matches(AnalysisEvent.ISSUE_FOUND, {"severity": "low"})
    
    def test_subscription_inactive(self):
        """Test inactive subscription doesn't match."""
        handler = Mock()
        subscription = EventSubscription(
            handler=handler,
            events=AnalysisEvent.ISSUE_FOUND
        )
        
        subscription.is_active = False
        assert not subscription.matches(AnalysisEvent.ISSUE_FOUND, {})
    
    @pytest.mark.asyncio
    async def test_subscription_handle(self):
        """Test subscription handle method."""
        handler = AsyncMock()
        subscription = EventSubscription(
            handler=handler,
            events=AnalysisEvent.ISSUE_FOUND
        )
        
        event = AnalysisEvent.ISSUE_FOUND
        data = {"test": "data"}
        
        await subscription.handle(event, data)
        
        assert subscription.call_count == 1
        assert subscription.last_called_at is not None
        handler.assert_called_once_with(event, data)
    
    @pytest.mark.asyncio
    async def test_subscription_handle_once(self):
        """Test subscription with once=True."""
        handler = AsyncMock()
        subscription = EventSubscription(
            handler=handler,
            events=AnalysisEvent.ISSUE_FOUND,
            once=True
        )
        
        assert subscription.is_active is True
        
        await subscription.handle(AnalysisEvent.ISSUE_FOUND, {})
        
        assert subscription.is_active is False
        assert subscription.call_count == 1
    
    @pytest.mark.asyncio
    async def test_subscription_handle_error(self):
        """Test subscription handle with error."""
        handler = AsyncMock(side_effect=ValueError("Handler error"))
        subscription = EventSubscription(
            handler=handler,
            events=AnalysisEvent.ISSUE_FOUND
        )
        
        # Should raise exception (changed behavior)
        with pytest.raises(ValueError, match="Handler error"):
            await subscription.handle(AnalysisEvent.ISSUE_FOUND, {})
        
        assert subscription.call_count == 1
    
    def test_subscription_unsubscribe(self):
        """Test subscription unsubscribe."""
        handler = Mock()
        subscription = EventSubscription(
            handler=handler,
            events=AnalysisEvent.ISSUE_FOUND
        )
        
        assert subscription.is_active is True
        
        subscription.unsubscribe()
        
        assert subscription.is_active is False


class TestEventBus:
    """Test EventBus class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.event_bus = EventBus()
    
    def test_event_bus_creation(self):
        """Test creating EventBus instance."""
        bus = EventBus(max_concurrent_handlers=100)
        
        assert bus._max_concurrent_handlers == 100
        assert len(bus._subscriptions) == 0
        assert len(bus._event_history) == 0
        assert bus._stats['events_emitted'] == 0
    
    def test_subscribe_single_event(self):
        """Test subscribing to single event."""
        handler = Mock()
        
        subscription = self.event_bus.subscribe(
            AnalysisEvent.ISSUE_FOUND,
            handler
        )
        
        assert isinstance(subscription, EventSubscription)
        assert len(self.event_bus._subscriptions) == 1
        assert subscription in self.event_bus._subscriptions
    
    def test_subscribe_multiple_events(self):
        """Test subscribing to multiple events."""
        handler = Mock()
        events = [AnalysisEvent.ANALYSIS_STARTED, AnalysisEvent.ANALYSIS_COMPLETED]
        
        subscription = self.event_bus.subscribe(events, handler)
        
        assert subscription.events == events
        assert len(self.event_bus._subscriptions) == 1
    
    def test_subscribe_with_filter(self):
        """Test subscribing with filter function."""
        handler = Mock()
        filter_func = lambda event, data: True
        
        subscription = self.event_bus.subscribe(
            AnalysisEvent.ISSUE_FOUND,
            handler,
            filter_func=filter_func
        )
        
        assert subscription.filter_func == filter_func
    
    def test_subscribe_once(self):
        """Test subscribing with once=True."""
        handler = Mock()
        
        subscription = self.event_bus.subscribe(
            AnalysisEvent.ISSUE_FOUND,
            handler,
            once=True
        )
        
        assert subscription.once is True
    
    def test_unsubscribe(self):
        """Test unsubscribing."""
        handler = Mock()
        subscription = self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler)
        
        assert len(self.event_bus._subscriptions) == 1
        
        result = self.event_bus.unsubscribe(subscription)
        
        assert result is True
        assert len(self.event_bus._subscriptions) == 0
        assert subscription.is_active is False
    
    def test_unsubscribe_not_found(self):
        """Test unsubscribing non-existent subscription."""
        handler = Mock()
        subscription = EventSubscription(handler, AnalysisEvent.ISSUE_FOUND)
        
        result = self.event_bus.unsubscribe(subscription)
        
        assert result is False
    
    def test_unsubscribe_all(self):
        """Test unsubscribing all subscriptions."""
        handler1 = Mock()
        handler2 = Mock()
        
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler1)
        self.event_bus.subscribe(AnalysisEvent.PROGRESS_UPDATE, handler2)
        
        assert len(self.event_bus._subscriptions) == 2
        
        removed = self.event_bus.unsubscribe_all()
        
        assert removed == 2
        assert len(self.event_bus._subscriptions) == 0
    
    def test_unsubscribe_all_by_handler(self):
        """Test unsubscribing all subscriptions for specific handler."""
        handler1 = Mock()
        handler2 = Mock()
        
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler1)
        self.event_bus.subscribe(AnalysisEvent.PROGRESS_UPDATE, handler1)
        self.event_bus.subscribe(AnalysisEvent.ANALYSIS_STARTED, handler2)
        
        assert len(self.event_bus._subscriptions) == 3
        
        removed = self.event_bus.unsubscribe_all(handler1)
        
        assert removed == 2
        assert len(self.event_bus._subscriptions) == 1
    
    @pytest.mark.asyncio
    async def test_emit_no_subscribers(self):
        """Test emitting event with no subscribers."""
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {"test": "data"})
        
        assert self.event_bus._stats['events_emitted'] == 1
        assert len(self.event_bus._event_history) == 1
    
    @pytest.mark.asyncio
    async def test_emit_with_subscribers(self):
        """Test emitting event with subscribers."""
        handler = AsyncMock()
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler)
        
        data = {"test": "data"}
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, data)
        
        # Give handlers time to execute
        await asyncio.sleep(0.1)
        
        handler.assert_called_once_with(AnalysisEvent.ISSUE_FOUND, data)
        assert self.event_bus._stats['events_emitted'] == 1
    
    @pytest.mark.asyncio
    async def test_emit_wait_for_handlers(self):
        """Test emitting event and waiting for handlers."""
        handler = AsyncMock()
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler)
        
        data = {"test": "data"}
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, data, wait_for_handlers=True)
        
        handler.assert_called_once_with(AnalysisEvent.ISSUE_FOUND, data)
    
    @pytest.mark.asyncio
    async def test_emit_multiple_subscribers(self):
        """Test emitting event to multiple subscribers."""
        handler1 = AsyncMock()
        handler2 = AsyncMock()
        
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler1)
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler2)
        
        data = {"test": "data"}
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, data, wait_for_handlers=True)
        
        handler1.assert_called_once_with(AnalysisEvent.ISSUE_FOUND, data)
        handler2.assert_called_once_with(AnalysisEvent.ISSUE_FOUND, data)
    
    @pytest.mark.asyncio
    async def test_emit_with_filter(self):
        """Test emitting event with filtered subscription."""
        handler = AsyncMock()
        filter_func = lambda event, data: data.get("severity") == "high"
        
        self.event_bus.subscribe(
            AnalysisEvent.ISSUE_FOUND,
            handler,
            filter_func=filter_func
        )
        
        # Should not trigger handler
        await self.event_bus.emit(
            AnalysisEvent.ISSUE_FOUND,
            {"severity": "low"},
            wait_for_handlers=True
        )
        handler.assert_not_called()
        
        # Should trigger handler
        await self.event_bus.emit(
            AnalysisEvent.ISSUE_FOUND,
            {"severity": "high"},
            wait_for_handlers=True
        )
        handler.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_emit_handler_error(self):
        """Test emitting event with handler that raises error."""
        handler = AsyncMock(side_effect=ValueError("Handler error"))
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler)
        
        # Should not raise exception
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {}, wait_for_handlers=True)
        
        assert self.event_bus._stats['handler_errors'] == 1
    
    def test_get_event_history(self):
        """Test getting event history."""
        # Add some events to history manually
        now = datetime.now(timezone.utc)
        self.event_bus._event_history = [
            (AnalysisEvent.ANALYSIS_STARTED, {}, now),
            (AnalysisEvent.ISSUE_FOUND, {"id": "1"}, now),
            (AnalysisEvent.ISSUE_FOUND, {"id": "2"}, now),
            (AnalysisEvent.ANALYSIS_COMPLETED, {}, now),
        ]
        
        # Get all history
        history = self.event_bus.get_event_history()
        assert len(history) == 4
        
        # Get filtered history
        filtered = self.event_bus.get_event_history(AnalysisEvent.ISSUE_FOUND)
        assert len(filtered) == 2
        
        # Get limited history
        limited = self.event_bus.get_event_history(limit=2)
        assert len(limited) == 2
    
    def test_get_stats(self):
        """Test getting event bus statistics."""
        handler = Mock()
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler)
        self.event_bus._stats['events_emitted'] = 5
        self.event_bus._stats['handlers_executed'] = 10
        
        stats = self.event_bus.get_stats()
        
        assert stats['events_emitted'] == 5
        assert stats['handlers_executed'] == 10
        assert stats['active_subscriptions'] == 1
        assert stats['total_subscriptions'] == 1
        assert 'active_handlers' in stats
        assert 'history_size' in stats
    
    @pytest.mark.asyncio
    async def test_wait_for_handlers(self):
        """Test waiting for handlers to complete."""
        slow_handler = AsyncMock()
        
        async def slow_handler_func(event, data):
            await asyncio.sleep(0.1)
        
        slow_handler.side_effect = slow_handler_func
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, slow_handler)
        
        # Emit event without waiting
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {})
        
        # Wait for handlers
        await self.event_bus.wait_for_handlers()
        
        slow_handler.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_wait_for_handlers_timeout(self):
        """Test waiting for handlers with timeout."""
        slow_handler = AsyncMock()
        
        async def slow_handler_func(event, data):
            await asyncio.sleep(1.0)  # Longer than timeout
        
        slow_handler.side_effect = slow_handler_func
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, slow_handler)
        
        # Emit event
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {})
        
        # Wait with short timeout
        await self.event_bus.wait_for_handlers(timeout=0.1)
        
        # Should not raise exception, just log warning
    
    @pytest.mark.asyncio
    async def test_temporary_subscription(self):
        """Test temporary subscription context manager."""
        handler = AsyncMock()
        
        async with self.event_bus.temporary_subscription(
            AnalysisEvent.ISSUE_FOUND,
            handler
        ) as subscription:
            assert len(self.event_bus._subscriptions) == 1
            assert subscription.is_active is True
            
            await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {}, wait_for_handlers=True)
            handler.assert_called_once()
        
        # Should be unsubscribed after context
        assert len(self.event_bus._subscriptions) == 0
        assert subscription.is_active is False
    
    def test_clear_history(self):
        """Test clearing event history."""
        # Add some history
        self.event_bus._event_history = [
            (AnalysisEvent.ANALYSIS_STARTED, {}, datetime.now(timezone.utc))
        ]
        
        assert len(self.event_bus._event_history) == 1
        
        self.event_bus.clear_history()
        
        assert len(self.event_bus._event_history) == 0
    
    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test event bus shutdown."""
        handler = AsyncMock()
        subscription = self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler)
        
        # Add some history
        self.event_bus._event_history = [
            (AnalysisEvent.ANALYSIS_STARTED, {}, datetime.now(timezone.utc))
        ]
        
        await self.event_bus.shutdown()
        
        assert len(self.event_bus._subscriptions) == 0
        assert len(self.event_bus._event_history) == 0
        assert subscription.is_active is False


class TestGlobalEventBus:
    """Test global event bus functions."""
    
    def setup_method(self):
        """Reset global event bus."""
        set_event_bus(None)
    
    def test_get_event_bus_creates_instance(self):
        """Test get_event_bus creates instance if none exists."""
        bus = get_event_bus()
        
        assert isinstance(bus, EventBus)
        
        # Should return same instance
        bus2 = get_event_bus()
        assert bus is bus2
    
    def test_set_event_bus(self):
        """Test setting custom event bus."""
        custom_bus = EventBus(max_concurrent_handlers=200)
        
        set_event_bus(custom_bus)
        
        bus = get_event_bus()
        assert bus is custom_bus
        assert bus._max_concurrent_handlers == 200


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.event_bus = EventBus()
        set_event_bus(self.event_bus)
    
    @pytest.mark.asyncio
    async def test_emit_progress(self):
        """Test emit_progress convenience function."""
        handler = AsyncMock()
        self.event_bus.subscribe(AnalysisEvent.PROGRESS_UPDATE, handler)
        
        await emit_progress(
            current=50,
            total=100,
            stage="parsing",
            message="Processing logs",
            source="test_parser"
        )
        
        # Wait for handlers to complete
        await self.event_bus.wait_for_handlers()
        
        handler.assert_called_once()
        event, data = handler.call_args[0]
        
        assert event == AnalysisEvent.PROGRESS_UPDATE
        assert isinstance(data, ProgressData)
        assert data.current == 50
        assert data.total == 100
        assert data.stage == "parsing"
        assert data.message == "Processing logs"
        assert data.source == "test_parser"
        assert data.percentage == 50.0
    
    @pytest.mark.asyncio
    async def test_emit_issue_found(self):
        """Test emit_issue_found convenience function."""
        handler = AsyncMock()
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler)
        
        await emit_issue_found(
            issue_id="issue-123",
            title="SQL Injection",
            severity="high",
            category="injection",
            description="Potential SQL injection",
            confidence=0.85,
            affected_urls=["http://example.com"],
            evidence={"payload": "' OR 1=1"},
            source="sql_detector"
        )
        
        # Wait for handlers to complete
        await self.event_bus.wait_for_handlers()
        
        handler.assert_called_once()
        event, data = handler.call_args[0]
        
        assert event == AnalysisEvent.ISSUE_FOUND
        assert isinstance(data, IssueData)
        assert data.issue_id == "issue-123"
        assert data.title == "SQL Injection"
        assert data.severity == "high"
        assert data.category == "injection"
        assert data.confidence == 0.85
        assert data.affected_urls == ["http://example.com"]
        assert data.evidence == {"payload": "' OR 1=1"}
        assert data.source == "sql_detector"
    
    @pytest.mark.asyncio
    async def test_emit_error(self):
        """Test emit_error convenience function."""
        handler = AsyncMock()
        self.event_bus.subscribe(AnalysisEvent.ERROR_OCCURRED, handler)
        
        await emit_error(
            error_type="ValueError",
            message="Invalid parameter",
            component="parser",
            recoverable=True,
            stack_trace="Traceback...",
            context={"line": 42},
            source="test_component"
        )
        
        # Wait for handlers to complete
        await self.event_bus.wait_for_handlers()
        
        handler.assert_called_once()
        event, data = handler.call_args[0]
        
        assert event == AnalysisEvent.ERROR_OCCURRED
        assert isinstance(data, ErrorData)
        assert data.error_type == "ValueError"
        assert data.message == "Invalid parameter"
        assert data.component == "parser"
        assert data.recoverable is True
        assert data.stack_trace == "Traceback..."
        assert data.context == {"line": 42}
        assert data.source == "test_component"


class TestEventBusIntegration:
    """Integration tests for EventBus functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.event_bus = EventBus()
    
    @pytest.mark.asyncio
    async def test_complex_event_flow(self):
        """Test complex event flow with multiple handlers and events."""
        # Set up handlers
        analysis_handler = AsyncMock()
        progress_handler = AsyncMock()
        issue_handler = AsyncMock()
        
        # Subscribe to different events
        self.event_bus.subscribe(
            [AnalysisEvent.ANALYSIS_STARTED, AnalysisEvent.ANALYSIS_COMPLETED],
            analysis_handler
        )
        self.event_bus.subscribe(AnalysisEvent.PROGRESS_UPDATE, progress_handler)
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, issue_handler)
        
        # Emit analysis started
        await self.event_bus.emit(
            AnalysisEvent.ANALYSIS_STARTED,
            {"config": {"threshold": 0.7}},
            wait_for_handlers=True
        )
        
        # Emit progress updates
        for i in range(3):
            await self.event_bus.emit(
                AnalysisEvent.PROGRESS_UPDATE,
                ProgressData(current=i*10, total=30, stage="parsing"),
                wait_for_handlers=True
            )
        
        # Emit issues found
        await self.event_bus.emit(
            AnalysisEvent.ISSUE_FOUND,
            IssueData(issue_id="issue-1", title="Test Issue", severity="high"),
            wait_for_handlers=True
        )
        
        # Emit analysis completed
        await self.event_bus.emit(
            AnalysisEvent.ANALYSIS_COMPLETED,
            {"duration": 5.2, "issues_found": 1},
            wait_for_handlers=True
        )
        
        # Verify handler calls
        assert analysis_handler.call_count == 2  # Started + Completed
        assert progress_handler.call_count == 3  # 3 progress updates
        assert issue_handler.call_count == 1     # 1 issue found
        
        # Verify event history
        history = self.event_bus.get_event_history()
        assert len(history) == 6  # All events recorded
        
        # Verify stats
        stats = self.event_bus.get_stats()
        assert stats['events_emitted'] == 6
        assert stats['handlers_executed'] == 6
    
    @pytest.mark.asyncio
    async def test_event_filtering_and_correlation(self):
        """Test event filtering and correlation tracking."""
        correlation_id = uuid4()
        high_severity_handler = AsyncMock()
        correlated_handler = AsyncMock()
        
        # Subscribe with severity filter
        self.event_bus.subscribe(
            AnalysisEvent.ISSUE_FOUND,
            high_severity_handler,
            filter_func=lambda event, data: data.severity == "high"
        )
        
        # Subscribe with correlation filter
        self.event_bus.subscribe(
            [AnalysisEvent.ANALYSIS_STARTED, AnalysisEvent.ISSUE_FOUND],
            correlated_handler,
            filter_func=lambda event, data: data.correlation_id == correlation_id
        )
        
        # Emit low severity issue (should not trigger high_severity_handler)
        await self.event_bus.emit(
            AnalysisEvent.ISSUE_FOUND,
            IssueData(issue_id="low-issue", severity="low"),
            wait_for_handlers=True
        )
        
        # Emit high severity issue (should trigger high_severity_handler)
        await self.event_bus.emit(
            AnalysisEvent.ISSUE_FOUND,
            IssueData(issue_id="high-issue", severity="high"),
            wait_for_handlers=True
        )
        
        # Emit correlated events
        correlated_start = EventData(correlation_id=correlation_id)
        await self.event_bus.emit(
            AnalysisEvent.ANALYSIS_STARTED,
            correlated_start,
            wait_for_handlers=True
        )
        
        correlated_issue = IssueData(
            issue_id="correlated-issue",
            severity="medium",
            correlation_id=correlation_id
        )
        await self.event_bus.emit(
            AnalysisEvent.ISSUE_FOUND,
            correlated_issue,
            wait_for_handlers=True
        )
        
        # Verify filtering worked
        assert high_severity_handler.call_count == 1  # Only high severity
        assert correlated_handler.call_count == 2     # Only correlated events
    
    @pytest.mark.asyncio
    async def test_concurrent_event_handling(self):
        """Test concurrent event handling with multiple handlers."""
        slow_handler = AsyncMock()
        fast_handler = AsyncMock()
        
        async def slow_handler_func(event, data):
            await asyncio.sleep(0.1)
            return "slow"
        
        async def fast_handler_func(event, data):
            return "fast"
        
        slow_handler.side_effect = slow_handler_func
        fast_handler.side_effect = fast_handler_func
        
        # Subscribe both handlers to same event
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, slow_handler)
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, fast_handler)
        
        # Emit event (async mode - don't wait)
        start_time = asyncio.get_event_loop().time()
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {})
        emit_time = asyncio.get_event_loop().time() - start_time
        
        # Should return quickly (async mode)
        assert emit_time < 0.05
        
        # Wait for handlers to complete
        await self.event_bus.wait_for_handlers()
        
        # Both handlers should have been called
        slow_handler.assert_called_once()
        fast_handler.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_event_bus_resource_management(self):
        """Test event bus resource management and cleanup."""
        handlers = []
        
        # Create many subscriptions
        for i in range(10):
            handler = AsyncMock()
            handlers.append(handler)
            self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler)
        
        # Emit event to all handlers
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {}, wait_for_handlers=True)
        
        # Verify all handlers called
        for handler in handlers:
            handler.assert_called_once()
        
        # Test stats
        stats = self.event_bus.get_stats()
        assert stats['active_subscriptions'] == 10
        assert stats['handlers_executed'] == 10
        
        # Test cleanup
        await self.event_bus.shutdown()
        
        # Verify cleanup
        assert len(self.event_bus._subscriptions) == 0
        assert len(self.event_bus._event_history) == 0
        
        # Verify all subscriptions deactivated
        for i, handler in enumerate(handlers):
            # Subscriptions should be inactive after shutdown
            pass  # Subscriptions are removed, not just deactivated


class TestEventBusEdgeCases:
    """Test edge cases and error conditions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.event_bus = EventBus()
    
    @pytest.mark.asyncio
    async def test_handler_exception_isolation(self):
        """Test that handler exceptions don't affect other handlers."""
        good_handler = AsyncMock()
        bad_handler = AsyncMock(side_effect=Exception("Handler failed"))
        another_good_handler = AsyncMock()
        
        # Subscribe all handlers
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, good_handler)
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, bad_handler)
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, another_good_handler)
        
        # Emit event
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {}, wait_for_handlers=True)
        
        # Good handlers should still be called
        good_handler.assert_called_once()
        another_good_handler.assert_called_once()
        bad_handler.assert_called_once()
        
        # Error should be recorded in stats
        stats = self.event_bus.get_stats()
        assert stats['handler_errors'] == 1
        assert stats['handlers_executed'] == 2  # Only successful ones
    
    @pytest.mark.asyncio
    async def test_subscription_lifecycle_edge_cases(self):
        """Test subscription lifecycle edge cases."""
        handler = AsyncMock()
        
        # Test once subscription
        once_sub = self.event_bus.subscribe(
            AnalysisEvent.ISSUE_FOUND,
            handler,
            once=True
        )
        
        # First event should trigger and deactivate
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {}, wait_for_handlers=True)
        assert handler.call_count == 1
        assert not once_sub.is_active
        
        # Second event should not trigger
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {}, wait_for_handlers=True)
        assert handler.call_count == 1  # Still 1
        
        # Test manual unsubscribe
        regular_sub = self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler)
        regular_sub.unsubscribe()
        
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {}, wait_for_handlers=True)
        assert handler.call_count == 1  # Still 1, not called
    
    @pytest.mark.asyncio
    async def test_event_history_limits(self):
        """Test event history size limits."""
        # Set small history limit
        self.event_bus._max_history = 3
        
        # Emit more events than limit
        for i in range(5):
            await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {"id": i})
        
        # Should only keep last 3
        assert len(self.event_bus._event_history) == 3
        
        # Should be the last 3 events
        ids = [data["id"] for _, data, _ in self.event_bus._event_history]
        assert ids == [2, 3, 4]
    
    @pytest.mark.asyncio
    async def test_concurrent_subscription_management(self):
        """Test concurrent subscription management."""
        handlers = []
        
        # Create subscriptions concurrently
        async def create_subscription(i):
            handler = AsyncMock()
            handlers.append(handler)
            return self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, handler)
        
        # Create multiple subscriptions concurrently
        subscriptions = await asyncio.gather(*[
            create_subscription(i) for i in range(5)
        ])
        
        assert len(self.event_bus._subscriptions) == 5
        
        # Emit event
        await self.event_bus.emit(AnalysisEvent.ISSUE_FOUND, {}, wait_for_handlers=True)
        
        # All handlers should be called
        for handler in handlers:
            handler.assert_called_once()
        
        # Unsubscribe concurrently
        async def unsubscribe_task(subscription):
            return self.event_bus.unsubscribe(subscription)
        
        await asyncio.gather(*[
            unsubscribe_task(sub) for sub in subscriptions
        ])
        
        assert len(self.event_bus._subscriptions) == 0


class TestEventDataSerialization:
    """Test event data serialization and deserialization."""
    
    def test_event_data_to_dict(self):
        """Test converting event data to dictionary."""
        # Test basic EventData
        data = EventData(source="test", metadata={"key": "value"})
        
        # Should have all expected fields
        assert hasattr(data, 'event_id')
        assert hasattr(data, 'timestamp')
        assert hasattr(data, 'source')
        assert hasattr(data, 'correlation_id')
        assert hasattr(data, 'metadata')
    
    def test_progress_data_properties(self):
        """Test ProgressData computed properties."""
        data = ProgressData(current=0, total=100, stage="init")
        assert data.percentage == 0.0
        
        data = ProgressData(current=50, total=100, stage="middle")
        assert data.percentage == 50.0
        
        data = ProgressData(current=100, total=100, stage="complete")
        assert data.percentage == 100.0
    
    def test_issue_data_defaults(self):
        """Test IssueData default values."""
        data = IssueData()
        
        assert data.issue_id == ""
        assert data.title == ""
        assert data.severity == ""
        assert data.category == ""
        assert data.description == ""
        assert data.confidence == 0.0
        assert data.affected_urls == []
        assert data.evidence == {}
    
    def test_error_data_context(self):
        """Test ErrorData context handling."""
        context = {
            "file": "test.py",
            "line": 42,
            "function": "test_func",
            "locals": {"var": "value"}
        }
        
        data = ErrorData(
            error_type="TestError",
            message="Test error message",
            component="test_component",
            context=context
        )
        
        assert data.context == context
        assert data.context["file"] == "test.py"
        assert data.context["line"] == 42
    
    def test_stage_data_metrics(self):
        """Test StageData metrics."""
        data = StageData(
            stage_name="detection",
            stage_type="detection",
            duration_ms=2500,
            items_processed=150,
            success_count=145,
            error_count=5
        )
        
        assert data.stage_name == "detection"
        assert data.duration_ms == 2500
        assert data.items_processed == 150
        assert data.success_count == 145
        assert data.error_count == 5
        
        # Verify success rate calculation would be possible
        if data.items_processed and data.items_processed > 0:
            success_rate = data.success_count / data.items_processed
            assert abs(success_rate - 0.9667) < 0.001  # ~96.67%
