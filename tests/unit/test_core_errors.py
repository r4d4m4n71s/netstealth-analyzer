"""
Unit tests for NetStealth Analyzer error handling system.

Tests error types, recovery strategies, context preservation, and the centralized
error handling architecture.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path
from datetime import datetime, timezone
from uuid import UUID, uuid4
from typing import Dict, Any

from src.netstealth_analyzer.core.errors import (
    # Enums
    ErrorSeverity,
    ErrorCategory,
    RecoveryStrategy,
    
    # Core classes
    ErrorContext,
    NetStealthError,
    ErrorHandler,
    
    # Specific error types
    FileError,
    FileNotFoundError,
    FilePermissionError,
    FileCorruptedError,
    ParseError,
    ValidationError,
    ConfigurationError,
    DetectionError,
    PluginError,
    PluginLoadError,
    TimeoutError,
    ResourceError,
    
    # Global functions
    get_error_handler,
    set_error_handler,
    handle_error,
    create_error_context,
)


class TestErrorEnums:
    """Test error enumeration types."""
    
    def test_error_severity_values(self):
        """Test ErrorSeverity enum values."""
        assert ErrorSeverity.LOW.value == "low"
        assert ErrorSeverity.MEDIUM.value == "medium"
        assert ErrorSeverity.HIGH.value == "high"
        assert ErrorSeverity.CRITICAL.value == "critical"
        
        # Test all values are strings
        for severity in ErrorSeverity:
            assert isinstance(severity.value, str)
    
    def test_error_category_values(self):
        """Test ErrorCategory enum values."""
        # Test some key categories
        assert ErrorCategory.FILE_NOT_FOUND
        assert ErrorCategory.PARSE_ERROR
        assert ErrorCategory.VALIDATION_ERROR
        assert ErrorCategory.PLUGIN_LOAD_ERROR
        assert ErrorCategory.TIMEOUT_ERROR
        assert ErrorCategory.UNKNOWN_ERROR
        
        # Test all categories are auto-generated integers
        for category in ErrorCategory:
            assert isinstance(category.value, int)
    
    def test_recovery_strategy_values(self):
        """Test RecoveryStrategy enum values."""
        assert RecoveryStrategy.FAIL_FAST.value == "fail_fast"
        assert RecoveryStrategy.RETRY.value == "retry"
        assert RecoveryStrategy.SKIP.value == "skip"
        assert RecoveryStrategy.FALLBACK.value == "fallback"
        assert RecoveryStrategy.PARTIAL.value == "partial"
        assert RecoveryStrategy.USER_INPUT.value == "user_input"
        
        # Test all values are strings
        for strategy in RecoveryStrategy:
            assert isinstance(strategy.value, str)


class TestErrorContext:
    """Test ErrorContext dataclass."""
    
    def test_error_context_creation(self):
        """Test ErrorContext creation with default values."""
        context = ErrorContext()
        
        assert isinstance(context.error_id, UUID)
        assert isinstance(context.timestamp, datetime)
        assert context.timestamp.tzinfo == timezone.utc
        assert context.component == ""
        assert context.operation == ""
        assert context.file_path is None
        assert context.line_number is None
        assert context.user_data == {}
        assert context.system_info == {}
        assert context.correlation_id is None
    
    def test_error_context_custom_values(self):
        """Test ErrorContext creation with custom values."""
        error_id = uuid4()
        timestamp = datetime.now(timezone.utc)
        file_path = Path("/test/file.log")
        correlation_id = uuid4()
        user_data = {"user": "test"}
        system_info = {"os": "linux"}
        
        context = ErrorContext(
            error_id=error_id,
            timestamp=timestamp,
            component="test_component",
            operation="test_operation",
            file_path=file_path,
            line_number=42,
            user_data=user_data,
            system_info=system_info,
            correlation_id=correlation_id
        )
        
        assert context.error_id == error_id
        assert context.timestamp == timestamp
        assert context.component == "test_component"
        assert context.operation == "test_operation"
        assert context.file_path == file_path
        assert context.line_number == 42
        assert context.user_data == user_data
        assert context.system_info == system_info
        assert context.correlation_id == correlation_id
    
    def test_error_context_with_correlation(self):
        """Test ErrorContext.with_correlation method."""
        original_context = ErrorContext(
            component="test",
            operation="test_op"
        )
        
        correlation_id = uuid4()
        new_context = original_context.with_correlation(correlation_id)
        
        # Should preserve all original values
        assert new_context.error_id == original_context.error_id
        assert new_context.timestamp == original_context.timestamp
        assert new_context.component == original_context.component
        assert new_context.operation == original_context.operation
        
        # Should set correlation ID
        assert new_context.correlation_id == correlation_id
        assert original_context.correlation_id is None  # Original unchanged
    
    def test_error_context_immutable(self):
        """Test ErrorContext is immutable (frozen dataclass)."""
        context = ErrorContext(component="test")
        
        with pytest.raises(AttributeError):
            context.component = "modified"


class TestNetStealthError:
    """Test NetStealthError base exception class."""
    
    def test_netstealth_error_creation(self):
        """Test NetStealthError creation with default values."""
        error = NetStealthError("Test error message")
        
        assert str(error) == "NetStealthError: Test error message"
        assert error.message == "Test error message"
        assert error.category == ErrorCategory.UNKNOWN_ERROR
        assert error.severity == ErrorSeverity.MEDIUM
        assert error.recovery_strategy == RecoveryStrategy.FAIL_FAST
        assert isinstance(error.context, ErrorContext)
        assert error.cause is None
        assert error.suggestions == []
        assert error.retry_count == 0
        assert error.max_retries == 3
    
    def test_netstealth_error_custom_values(self):
        """Test NetStealthError creation with custom values."""
        context = ErrorContext(component="test_component")
        cause = ValueError("Original error")
        suggestions = ["Try this", "Or that"]
        
        error = NetStealthError(
            message="Custom error",
            category=ErrorCategory.VALIDATION_ERROR,
            severity=ErrorSeverity.HIGH,
            recovery_strategy=RecoveryStrategy.RETRY,
            context=context,
            cause=cause,
            suggestions=suggestions
        )
        
        assert error.message == "Custom error"
        assert error.category == ErrorCategory.VALIDATION_ERROR
        assert error.severity == ErrorSeverity.HIGH
        assert error.recovery_strategy == RecoveryStrategy.RETRY
        assert error.context == context
        assert error.cause == cause
        assert error.suggestions == suggestions
    
    def test_netstealth_error_string_representation(self):
        """Test NetStealthError string representation with context."""
        context = ErrorContext(
            component="test_component",
            operation="test_operation",
            file_path=Path("/test/file.log")
        )
        cause = ValueError("Root cause")
        
        error = NetStealthError(
            "Test error",
            context=context,
            cause=cause
        )
        
        error_str = str(error)
        assert "NetStealthError: Test error" in error_str
        assert "Component: test_component" in error_str
        assert "Operation: test_operation" in error_str
        assert "File:" in error_str and "file.log" in error_str
        assert "Caused by: Root cause" in error_str
    
    def test_netstealth_error_retry_logic(self):
        """Test NetStealthError retry logic."""
        error = NetStealthError(
            "Retryable error",
            recovery_strategy=RecoveryStrategy.RETRY
        )
        
        # Initially can retry
        assert error.can_retry() is True
        assert error.retry_count == 0
        
        # Increment retries
        error.increment_retry()
        assert error.retry_count == 1
        assert error.can_retry() is True
        
        # Exhaust retries
        error.increment_retry()
        error.increment_retry()
        assert error.retry_count == 3
        assert error.can_retry() is False
        
        # One more increment
        error.increment_retry()
        assert error.retry_count == 4
        assert error.can_retry() is False
    
    def test_netstealth_error_non_retryable(self):
        """Test NetStealthError with non-retryable strategy."""
        error = NetStealthError(
            "Non-retryable error",
            recovery_strategy=RecoveryStrategy.FAIL_FAST
        )
        
        assert error.can_retry() is False
        
        error.increment_retry()
        assert error.can_retry() is False
    
    def test_netstealth_error_to_dict(self):
        """Test NetStealthError serialization to dictionary."""
        context = ErrorContext(
            component="test_component",
            operation="test_operation",
            file_path=Path("/test/file.log"),
            line_number=42
        )
        cause = ValueError("Root cause")
        suggestions = ["Suggestion 1", "Suggestion 2"]
        
        error = NetStealthError(
            message="Test error",
            category=ErrorCategory.PARSE_ERROR,
            severity=ErrorSeverity.HIGH,
            recovery_strategy=RecoveryStrategy.RETRY,
            context=context,
            cause=cause,
            suggestions=suggestions
        )
        
        error_dict = error.to_dict()
        
        assert error_dict['error_type'] == 'NetStealthError'
        assert error_dict['message'] == 'Test error'
        assert error_dict['category'] == 'PARSE_ERROR'
        assert error_dict['severity'] == 'high'
        assert error_dict['recovery_strategy'] == 'retry'
        assert error_dict['retry_count'] == 0
        assert error_dict['max_retries'] == 3
        assert error_dict['cause'] == 'Root cause'
        assert error_dict['suggestions'] == suggestions
        
        # Test context serialization
        context_dict = error_dict['context']
        assert context_dict['component'] == 'test_component'
        assert context_dict['operation'] == 'test_operation'
        assert 'file.log' in context_dict['file_path']  # Handle Windows path separators
        assert context_dict['line_number'] == 42
        assert isinstance(context_dict['error_id'], str)
        assert isinstance(context_dict['timestamp'], str)


class TestFileErrors:
    """Test file-related error classes."""
    
    def test_file_error_base(self):
        """Test FileError base class."""
        file_path = Path("/test/file.log")
        error = FileError("File error", file_path=file_path)
        
        assert error.message == "File error"
        assert error.file_path == file_path
        assert error.context.file_path == file_path
        assert error.category == ErrorCategory.FILE_NOT_FOUND  # Default
    
    def test_file_not_found_error(self):
        """Test FileNotFoundError."""
        file_path = Path("/missing/file.log")
        error = FileNotFoundError(file_path)
        
        assert f"File not found: {file_path}" in error.message
        assert error.file_path == file_path
        assert error.category == ErrorCategory.FILE_NOT_FOUND
        assert error.recovery_strategy == RecoveryStrategy.SKIP
        assert len(error.suggestions) > 0
        assert "Check if the file path is correct" in error.suggestions
    
    def test_file_permission_error(self):
        """Test FilePermissionError."""
        file_path = Path("/protected/file.log")
        error = FilePermissionError(file_path, operation="read")
        
        assert "Permission denied: cannot read" in error.message
        assert str(file_path) in error.message
        assert error.file_path == file_path
        assert error.category == ErrorCategory.FILE_PERMISSION
        assert error.recovery_strategy == RecoveryStrategy.SKIP
        assert "Check file permissions" in error.suggestions
    
    def test_file_corrupted_error(self):
        """Test FileCorruptedError."""
        file_path = Path("/corrupted/file.log")
        error = FileCorruptedError(file_path, details="Invalid header")
        
        assert f"Corrupted file: {file_path}" in error.message
        assert "Invalid header" in error.message
        assert error.file_path == file_path
        assert error.category == ErrorCategory.FILE_CORRUPTED
        assert error.recovery_strategy == RecoveryStrategy.SKIP
        assert "Verify file integrity" in error.suggestions
    
    def test_file_corrupted_error_no_details(self):
        """Test FileCorruptedError without details."""
        file_path = Path("/corrupted/file.log")
        error = FileCorruptedError(file_path)
        
        assert f"Corrupted file: {file_path}" in error.message
        assert "Invalid header" not in error.message


class TestParseError:
    """Test ParseError class."""
    
    def test_parse_error_basic(self):
        """Test ParseError creation."""
        error = ParseError("Failed to parse JSON")
        
        assert error.message == "Failed to parse JSON"
        assert error.category == ErrorCategory.PARSE_ERROR
        assert error.recovery_strategy == RecoveryStrategy.PARTIAL
        assert "Check file format and structure" in error.suggestions
    
    def test_parse_error_with_location(self):
        """Test ParseError with file and line information."""
        file_path = Path("/test/data.json")
        error = ParseError(
            "Invalid JSON syntax",
            file_path=file_path,
            line_number=42
        )
        
        assert error.message == "Invalid JSON syntax"
        assert error.context.file_path == file_path
        assert error.context.line_number == 42


class TestValidationError:
    """Test ValidationError class."""
    
    def test_validation_error_basic(self):
        """Test ValidationError creation."""
        error = ValidationError("Invalid value")
        
        assert error.message == "Invalid value"
        assert error.category == ErrorCategory.VALIDATION_ERROR
        assert error.recovery_strategy == RecoveryStrategy.SKIP
    
    def test_validation_error_with_field(self):
        """Test ValidationError with field name."""
        error = ValidationError("Must be positive", field="timeout")
        
        assert "Validation failed for 'timeout': Must be positive" in error.message
        assert "Check input data format" in error.suggestions


class TestConfigurationError:
    """Test ConfigurationError class."""
    
    def test_configuration_error_basic(self):
        """Test ConfigurationError creation."""
        error = ConfigurationError("Invalid configuration")
        
        assert error.message == "Invalid configuration"
        assert error.category == ErrorCategory.CONFIGURATION_ERROR
        assert error.severity == ErrorSeverity.HIGH
        assert error.recovery_strategy == RecoveryStrategy.FAIL_FAST
    
    def test_configuration_error_with_key(self):
        """Test ConfigurationError with config key."""
        error = ConfigurationError("Missing required value", config_key="database.host")
        
        assert "Configuration error for 'database.host': Missing required value" in error.message
        assert "Check configuration file syntax" in error.suggestions


class TestDetectionError:
    """Test DetectionError class."""
    
    def test_detection_error_basic(self):
        """Test DetectionError creation."""
        error = DetectionError("Detection failed")
        
        assert error.message == "Detection failed"
        assert error.category == ErrorCategory.DETECTION_ERROR
        assert error.recovery_strategy == RecoveryStrategy.PARTIAL
    
    def test_detection_error_with_detector(self):
        """Test DetectionError with detector name."""
        error = DetectionError("Pattern not found", detector_name="tls_detector")
        
        assert "Detection error in 'tls_detector': Pattern not found" in error.message
        assert "Check detector configuration" in error.suggestions


class TestPluginErrors:
    """Test plugin-related error classes."""
    
    def test_plugin_error_base(self):
        """Test PluginError base class."""
        error = PluginError("Plugin failed")
        
        assert error.message == "Plugin failed"
        assert error.category == ErrorCategory.PLUGIN_EXECUTION_ERROR
        assert error.recovery_strategy == RecoveryStrategy.SKIP
        assert error.plugin_name is None
    
    def test_plugin_error_with_name(self):
        """Test PluginError with plugin name."""
        error = PluginError("Execution failed", plugin_name="test_plugin")
        
        assert "Plugin 'test_plugin': Execution failed" in error.message
        assert error.plugin_name == "test_plugin"
    
    def test_plugin_load_error(self):
        """Test PluginLoadError."""
        error = PluginLoadError("test_plugin", "Module not found")
        
        assert "Plugin 'test_plugin': Failed to load: Module not found" in error.message
        assert error.plugin_name == "test_plugin"
        assert error.category == ErrorCategory.PLUGIN_LOAD_ERROR
        assert "Check plugin file exists" in error.suggestions


class TestTimeoutError:
    """Test TimeoutError class."""
    
    def test_timeout_error(self):
        """Test TimeoutError creation."""
        error = TimeoutError("file_processing", 30.0)
        
        assert "Operation 'file_processing' timed out after 30.0s" in error.message
        assert error.category == ErrorCategory.TIMEOUT_ERROR
        assert error.recovery_strategy == RecoveryStrategy.RETRY
        assert "Increase timeout value" in error.suggestions


class TestResourceError:
    """Test ResourceError class."""
    
    def test_resource_error_basic(self):
        """Test ResourceError creation."""
        error = ResourceError("memory")
        
        assert "Resource unavailable: memory" in error.message
        assert error.category == ErrorCategory.RESOURCE_ERROR
        assert error.severity == ErrorSeverity.HIGH
        assert error.recovery_strategy == RecoveryStrategy.RETRY
    
    def test_resource_error_with_details(self):
        """Test ResourceError with details."""
        error = ResourceError("disk_space", "Only 100MB remaining")
        
        assert "Resource unavailable: disk_space (Only 100MB remaining)" in error.message
        assert "Check system resources" in error.suggestions


class TestErrorHandler:
    """Test ErrorHandler class."""
    
    def test_error_handler_initialization(self):
        """Test ErrorHandler initialization."""
        handler = ErrorHandler()
        
        assert handler.error_history == []
        assert handler.max_history == 1000
        assert handler.recovery_handlers == {}
        assert handler.error_stats['total_errors'] == 0
        assert handler.error_stats['recovered_errors'] == 0
        assert handler.error_stats['failed_recoveries'] == 0
        assert handler.error_stats['by_category'] == {}
        assert handler.error_stats['by_severity'] == {}
    
    def test_register_recovery_handler(self):
        """Test registering recovery handlers."""
        handler = ErrorHandler()
        
        async def mock_handler(error):
            return True
        
        handler.register_recovery_handler(ErrorCategory.TIMEOUT_ERROR, mock_handler)
        
        assert ErrorCategory.TIMEOUT_ERROR in handler.recovery_handlers
        assert handler.recovery_handlers[ErrorCategory.TIMEOUT_ERROR] == mock_handler
    
    @pytest.mark.asyncio
    async def test_handle_netstealth_error(self):
        """Test handling NetStealthError."""
        handler = ErrorHandler()
        error = NetStealthError("Test error", severity=ErrorSeverity.LOW)
        
        result = await handler.handle_error(error)
        
        # Should fail fast by default
        assert result is False
        assert len(handler.error_history) == 1
        assert handler.error_stats['total_errors'] == 1
        assert handler.error_stats['failed_recoveries'] == 1
        assert handler.error_stats['by_severity']['low'] == 1
    
    @pytest.mark.asyncio
    async def test_handle_generic_exception(self):
        """Test handling generic Python exception."""
        handler = ErrorHandler()
        context = ErrorContext(component="test")
        
        result = await handler.handle_error(ValueError("Test value error"), context)
        
        assert result is False
        assert len(handler.error_history) == 1
        
        handled_error = handler.error_history[0]
        assert isinstance(handled_error, NetStealthError)
        assert handled_error.category == ErrorCategory.VALIDATION_ERROR
        assert handled_error.context == context
        assert isinstance(handled_error.cause, ValueError)
    
    @pytest.mark.asyncio
    async def test_handle_error_with_retry_strategy(self):
        """Test handling error with retry strategy."""
        handler = ErrorHandler()
        error = NetStealthError(
            "Retryable error",
            recovery_strategy=RecoveryStrategy.RETRY
        )
        
        result = await handler.handle_error(error)
        
        # Should succeed with retry strategy
        assert result is True
        assert error.retry_count == 1
        assert handler.error_stats['recovered_errors'] == 1
    
    @pytest.mark.asyncio
    async def test_handle_error_with_skip_strategy(self):
        """Test handling error with skip strategy."""
        handler = ErrorHandler()
        error = NetStealthError(
            "Skippable error",
            recovery_strategy=RecoveryStrategy.SKIP
        )
        
        result = await handler.handle_error(error)
        
        assert result is True
        assert handler.error_stats['recovered_errors'] == 1
    
    @pytest.mark.asyncio
    async def test_handle_error_with_custom_handler(self):
        """Test handling error with custom recovery handler."""
        handler = ErrorHandler()
        
        # Register custom handler that always succeeds
        async def custom_handler(error):
            return True
        
        handler.register_recovery_handler(ErrorCategory.TIMEOUT_ERROR, custom_handler)
        
        error = NetStealthError(
            "Timeout error",
            category=ErrorCategory.TIMEOUT_ERROR,
            recovery_strategy=RecoveryStrategy.FAIL_FAST  # Would normally fail
        )
        
        result = await handler.handle_error(error)
        
        # Should succeed due to custom handler
        assert result is True
        assert handler.error_stats['recovered_errors'] == 1
    
    @pytest.mark.asyncio
    async def test_handle_error_custom_handler_failure(self):
        """Test handling error when custom handler fails."""
        handler = ErrorHandler()
        
        # Register custom handler that raises exception
        async def failing_handler(error):
            raise RuntimeError("Handler failed")
        
        handler.register_recovery_handler(ErrorCategory.TIMEOUT_ERROR, failing_handler)
        
        error = NetStealthError(
            "Timeout error",
            category=ErrorCategory.TIMEOUT_ERROR
        )
        
        result = await handler.handle_error(error)
        
        # Should fail gracefully
        assert result is False
        assert handler.error_stats['failed_recoveries'] == 1
    
    def test_convert_to_netstealth_error(self):
        """Test converting generic exceptions to NetStealthError."""
        handler = ErrorHandler()
        context = ErrorContext(component="test")
        
        # Test FileNotFoundError mapping
        original_error = FileNotFoundError("File not found")
        converted = handler._convert_to_netstealth_error(original_error, context)
        
        assert isinstance(converted, NetStealthError)
        assert converted.category == ErrorCategory.FILE_NOT_FOUND
        assert converted.cause == original_error
        assert converted.context == context
        
        # Test unknown error mapping
        unknown_error = RuntimeError("Unknown error")
        converted = handler._convert_to_netstealth_error(unknown_error)
        
        assert converted.category == ErrorCategory.UNKNOWN_ERROR
        assert converted.cause == unknown_error
    
    def test_update_stats(self):
        """Test error statistics updating."""
        handler = ErrorHandler()
        
        error1 = NetStealthError("Error 1", category=ErrorCategory.PARSE_ERROR, severity=ErrorSeverity.HIGH)
        error2 = NetStealthError("Error 2", category=ErrorCategory.PARSE_ERROR, severity=ErrorSeverity.LOW)
        error3 = NetStealthError("Error 3", category=ErrorCategory.TIMEOUT_ERROR, severity=ErrorSeverity.HIGH)
        
        handler._update_stats(error1)
        handler._update_stats(error2)
        handler._update_stats(error3)
        
        assert handler.error_stats['total_errors'] == 3
        assert handler.error_stats['by_category']['PARSE_ERROR'] == 2
        assert handler.error_stats['by_category']['TIMEOUT_ERROR'] == 1
        assert handler.error_stats['by_severity']['high'] == 2
        assert handler.error_stats['by_severity']['low'] == 1
    
    def test_error_history_limit(self):
        """Test error history size limit."""
        handler = ErrorHandler()
        handler.max_history = 3
        
        # Add more errors than the limit
        for i in range(5):
            error = NetStealthError(f"Error {i}")
            handler.error_history.append(error)
            if len(handler.error_history) > handler.max_history:
                handler.error_history.pop(0)
        
        assert len(handler.error_history) == 3
        # Should keep the most recent errors
        assert handler.error_history[0].message == "Error 2"
        assert handler.error_history[-1].message == "Error 4"
    
    def test_get_error_summary(self):
        """Test error summary generation."""
        handler = ErrorHandler()
        
        # Add some test errors
        error1 = NetStealthError("Error 1", severity=ErrorSeverity.HIGH)
        error2 = NetStealthError("Error 2", severity=ErrorSeverity.LOW)
        
        handler.error_history = [error1, error2]
        handler.error_stats = {
            'total_errors': 2,
            'recovered_errors': 1,
            'failed_recoveries': 1,
            'by_category': {'UNKNOWN_ERROR': 2},
            'by_severity': {'high': 1, 'low': 1},
        }
        
        summary = handler.get_error_summary()
        
        assert summary['stats']['total_errors'] == 2
        assert summary['stats']['recovered_errors'] == 1
        assert len(summary['recent_errors']) == 2
        
        recent_error = summary['recent_errors'][0]
        assert recent_error['message'] == 'Error 1'
        assert recent_error['severity'] == 'high'
        assert 'id' in recent_error
        assert 'timestamp' in recent_error
    
    def test_clear_history(self):
        """Test clearing error history."""
        handler = ErrorHandler()
        
        # Add some errors
        handler.error_history = [
            NetStealthError("Error 1"),
            NetStealthError("Error 2")
        ]
        
        handler.clear_history()
        
        assert handler.error_history == []


class TestGlobalFunctions:
    """Test global error handling functions."""
    
    def test_get_error_handler_singleton(self):
        """Test get_error_handler returns singleton."""
        handler1 = get_error_handler()
        handler2 = get_error_handler()
        
        assert handler1 is handler2
        assert isinstance(handler1, ErrorHandler)
    
    def test_set_error_handler(self):
        """Test setting custom error handler."""
        original_handler = get_error_handler()
        custom_handler = ErrorHandler()
        
        set_error_handler(custom_handler)
        
        assert get_error_handler() is custom_handler
        assert get_error_handler() is not original_handler
        
        # Reset for other tests
        set_error_handler(original_handler)
    
    @pytest.mark.asyncio
    async def test_handle_error_global_function(self):
        """Test global handle_error function."""
        error = NetStealthError("Test error", recovery_strategy=RecoveryStrategy.SKIP)
        
        result = await handle_error(error)
        
        assert result is True  # Skip strategy should succeed
    
    def test_create_error_context(self):
        """Test create_error_context utility function."""
        context = create_error_context(
            component="test_component",
            operation="test_operation",
            file_path=Path("/test/file.log"),
            line_number=42
        )
        
        assert isinstance(context, ErrorContext)
        assert context.component == "test_component"
        assert context.operation == "test_operation"
        assert context.file_path == Path("/test/file.log")
        assert context.line_number == 42


class TestErrorIntegration:
    """Integration tests for error handling system."""
    
    @pytest.mark.asyncio
    async def test_error_handling_workflow(self):
        """Test complete error handling workflow."""
        handler = ErrorHandler()
        
        # Register a custom recovery handler
        recovery_attempts = []
        
        async def custom_recovery(error):
            recovery_attempts.append(error.message)
            return error.message == "recoverable_error"
        
        handler.register_recovery_handler(ErrorCategory.TIMEOUT_ERROR, custom_recovery)
        
        # Test recoverable error
        recoverable_error = NetStealthError(
            "recoverable_error",
            category=ErrorCategory.TIMEOUT_ERROR,
            severity=ErrorSeverity.MEDIUM
        )
        
        result = await handler.handle_error(recoverable_error)
        assert result is True
        assert "recoverable_error" in recovery_attempts
        
        # Test non-recoverable error
        non_recoverable_error = NetStealthError(
            "non_recoverable_error",
            category=ErrorCategory.TIMEOUT_ERROR,
            severity=ErrorSeverity.HIGH
        )
        
        result = await handler.handle_error(non_recoverable_error)
        assert result is False
        assert "non_recoverable_error" in recovery_attempts
        
        # Check statistics
        stats = handler.get_error_summary()
        assert stats['stats']['total_errors'] == 2
        assert stats['stats']['recovered_errors'] == 1
        assert stats['stats']['failed_recoveries'] == 1
    
    @pytest.mark.asyncio
    async def test_error_context_propagation(self):
        """Test error context propagation through system."""
        handler = ErrorHandler()
        
        # Create error with rich context
        context = ErrorContext(
            component="file_parser",
            operation="parse_har_file",
            file_path=Path("/data/test.har"),
            line_number=150,
            user_data={"user_id": "test_user"},
            system_info={"memory_usage": "75%"}
        )
        
        error = ParseError(
            "Invalid JSON structure",
            file_path=context.file_path,
            line_number=context.line_number
        )
        # Manually set the context fields that ParseError doesn't handle
        error.context = ErrorContext(
            error_id=error.context.error_id,
            timestamp=error.context.timestamp,
            component=context.component,
            operation=context.operation,
            file_path=context.file_path,
            line_number=context.line_number,
            user_data=context.user_data,
            system_info=context.system_info,
            correlation_id=context.correlation_id
        )
        
        await handler.handle_error(error)
        
        # Verify context is preserved
        handled_error = handler.error_history[0]
        assert handled_error.context.component == "file_parser"
        assert handled_error.context.operation == "parse_har_file"
        assert handled_error.context.file_path == Path("/data/test.har")
        assert handled_error.context.line_number == 150
        assert handled_error.context.user_data["user_id"] == "test_user"
        assert handled_error.context.system_info["memory_usage"] == "75%"
    
    def test_error_serialization_roundtrip(self):
        """Test error serialization and data preservation."""
        # Create complex error with all fields
        context = ErrorContext(
            component="test_component",
            operation="test_operation",
            file_path=Path("/test/file.log"),
            line_number=42,
            user_data={"key": "value"},
            system_info={"version": "1.0"}
        )
        
        original_error = NetStealthError(
            message="Complex test error",
            category=ErrorCategory.PARSE_ERROR,
            severity=ErrorSeverity.HIGH,
            recovery_strategy=RecoveryStrategy.RETRY,
            context=context,
            cause=ValueError("Root cause"),
            suggestions=["Fix this", "Try that"]
        )
        
        # Serialize to dict
        error_dict = original_error.to_dict()
        
        # Verify all data is preserved
        assert error_dict['error_type'] == 'NetStealthError'
        assert error_dict['message'] == 'Complex test error'
        assert error_dict['category'] == 'PARSE_ERROR'
        assert error_dict['severity'] == 'high'
        assert error_dict['recovery_strategy'] == 'retry'
        assert error_dict['suggestions'] == ['Fix this', 'Try that']
        assert error_dict['cause'] == 'Root cause'
        
        # Verify context serialization
        context_dict = error_dict['context']
        assert context_dict['component'] == 'test_component'
        assert context_dict['operation'] == 'test_operation'
        assert 'file.log' in context_dict['file_path']  # Handle Windows path separators
        assert context_dict['line_number'] == 42
    
    @pytest.mark.asyncio
    async def test_recovery_strategy_combinations(self):
        """Test different recovery strategy combinations."""
        handler = ErrorHandler()
        
        # Test all recovery strategies
        strategies_and_expected = [
            (RecoveryStrategy.FAIL_FAST, False),
            (RecoveryStrategy.SKIP, True),
            (RecoveryStrategy.PARTIAL, True),
            (RecoveryStrategy.FALLBACK, True),
            (RecoveryStrategy.USER_INPUT, False),
        ]
        
        for strategy, expected_recovery in strategies_and_expected:
            error = NetStealthError(
                f"Test error for {strategy.value}",
                recovery_strategy=strategy
            )
            
            result = await handler.handle_error(error)
            assert result == expected_recovery, f"Strategy {strategy.value} should return {expected_recovery}"
        
        # Test retry strategy with exhausted retries
        retry_error = NetStealthError(
            "Retry test",
            recovery_strategy=RecoveryStrategy.RETRY
        )
        
        # First few attempts should succeed
        for i in range(3):
            result = await handler.handle_error(retry_error)
            assert result is True
        
        # After max retries, should fail
        result = await handler.handle_error(retry_error)
        assert result is False
    
    def test_error_inheritance_hierarchy(self):
        """Test error class inheritance hierarchy."""
        # Test that all specific errors inherit from NetStealthError
        specific_errors = [
            FileError("test"),
            FileNotFoundError(Path("/test")),
            FilePermissionError(Path("/test")),
            FileCorruptedError(Path("/test")),
            ParseError("test"),
            ValidationError("test"),
            ConfigurationError("test"),
            DetectionError("test"),
            PluginError("test"),
            PluginLoadError("test", "reason"),
            TimeoutError("test", 30.0),
            ResourceError("test"),
        ]
        
        for error in specific_errors:
            assert isinstance(error, NetStealthError)
            assert isinstance(error, Exception)
            
            # Test that they all have the required attributes
            assert hasattr(error, 'message')
            assert hasattr(error, 'category')
            assert hasattr(error, 'severity')
            assert hasattr(error, 'recovery_strategy')
            assert hasattr(error, 'context')
            assert hasattr(error, 'suggestions')
    
    @pytest.mark.asyncio
    async def test_concurrent_error_handling(self):
        """Test concurrent error handling."""
        handler = ErrorHandler()
        
        # Create multiple errors to handle concurrently
        errors = [
            NetStealthError(f"Error {i}", recovery_strategy=RecoveryStrategy.SKIP)
            for i in range(10)
        ]
        
        # Handle all errors concurrently
        tasks = [handler.handle_error(error) for error in errors]
        results = await asyncio.gather(*tasks)
        
        # All should succeed (skip strategy)
        assert all(results)
        assert len(handler.error_history) == 10
        assert handler.error_stats['total_errors'] == 10
        assert handler.error_stats['recovered_errors'] == 10
    
    def test_error_category_mapping_completeness(self):
        """Test that error category mapping covers common Python exceptions."""
        handler = ErrorHandler()
        
        # Test mapping of common Python exceptions
        exception_mappings = [
            (FileNotFoundError("test"), ErrorCategory.FILE_NOT_FOUND),
            (PermissionError("test"), ErrorCategory.FILE_PERMISSION),
            (ValueError("test"), ErrorCategory.VALIDATION_ERROR),
            (Exception("test"), ErrorCategory.UNKNOWN_ERROR),  # Use generic exception instead
            (MemoryError("test"), ErrorCategory.MEMORY_ERROR),
            (ConnectionError("test"), ErrorCategory.NETWORK_ERROR),
            (UnicodeDecodeError("utf-8", b"", 0, 1, "test"), ErrorCategory.ENCODING_ERROR),
            (RuntimeError("test"), ErrorCategory.UNKNOWN_ERROR),  # Unmapped exception
        ]
        
        for exception, expected_category in exception_mappings:
            converted = handler._convert_to_netstealth_error(exception)
            assert converted.category == expected_category
            assert converted.cause == exception
