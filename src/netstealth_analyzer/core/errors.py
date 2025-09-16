"""
Structured error handling architecture for NetStealth Analyzer.

This module provides comprehensive error types, recovery strategies, and context
preservation for robust error handling throughout the analysis pipeline.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import asyncio
import traceback
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Union, Type, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4, UUID
from pathlib import Path
import logging

from ..compatibility import ExceptionGroup, override

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Severity levels for errors and exceptions."""
    
    LOW = "low"                    # Minor issues, analysis can continue
    MEDIUM = "medium"              # Moderate issues, some features may be affected
    HIGH = "high"                  # Serious issues, major functionality impacted
    CRITICAL = "critical"          # Critical failures, analysis cannot continue


class ErrorCategory(Enum):
    """Categories of errors for better classification and handling."""
    
    # Input/Output errors
    FILE_NOT_FOUND = auto()        # File or resource not found
    FILE_PERMISSION = auto()       # Permission denied accessing file
    FILE_CORRUPTED = auto()        # File is corrupted or invalid format
    NETWORK_ERROR = auto()         # Network connectivity issues
    
    # Parsing errors
    PARSE_ERROR = auto()           # Failed to parse log file or data
    FORMAT_ERROR = auto()          # Invalid or unsupported format
    ENCODING_ERROR = auto()        # Character encoding issues
    
    # Analysis errors
    DETECTION_ERROR = auto()       # Error in detection logic
    VALIDATION_ERROR = auto()      # Data validation failed
    CONFIGURATION_ERROR = auto()   # Invalid configuration
    
    # System errors
    MEMORY_ERROR = auto()          # Out of memory
    TIMEOUT_ERROR = auto()         # Operation timed out
    RESOURCE_ERROR = auto()        # System resource unavailable
    
    # Plugin errors
    PLUGIN_LOAD_ERROR = auto()     # Failed to load plugin
    PLUGIN_EXECUTION_ERROR = auto() # Plugin execution failed
    PLUGIN_DEPENDENCY_ERROR = auto() # Plugin dependency missing
    
    # Unknown/Other
    UNKNOWN_ERROR = auto()         # Unclassified error


class RecoveryStrategy(Enum):
    """Recovery strategies for different types of errors."""
    
    FAIL_FAST = "fail_fast"       # Stop immediately, no recovery
    RETRY = "retry"               # Retry the operation
    SKIP = "skip"                 # Skip the failed operation and continue
    FALLBACK = "fallback"         # Use alternative approach
    PARTIAL = "partial"           # Continue with partial results
    USER_INPUT = "user_input"     # Require user intervention


@dataclass(frozen=True)
class ErrorContext:
    """
    Context information for errors to aid in debugging and recovery.
    """
    
    error_id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    component: str = ""
    operation: str = ""
    file_path: Optional[Path] = None
    line_number: Optional[int] = None
    user_data: Dict[str, Any] = field(default_factory=dict)
    system_info: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[UUID] = None
    
    def with_correlation(self, correlation_id: UUID) -> 'ErrorContext':
        """Create a copy with correlation ID set."""
        return ErrorContext(
            error_id=self.error_id,
            timestamp=self.timestamp,
            component=self.component,
            operation=self.operation,
            file_path=self.file_path,
            line_number=self.line_number,
            user_data=self.user_data,
            system_info=self.system_info,
            correlation_id=correlation_id
        )


class NetStealthError(Exception):
    """
    Base exception class for all NetStealth Analyzer errors.
    
    Provides structured error information, context preservation,
    and recovery strategy hints.
    """
    
    def __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.UNKNOWN_ERROR,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        recovery_strategy: RecoveryStrategy = RecoveryStrategy.FAIL_FAST,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
        suggestions: Optional[List[str]] = None
    ):
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.recovery_strategy = recovery_strategy
        self.context = context or ErrorContext()
        self.cause = cause
        self.suggestions = suggestions or []
        self.retry_count = 0
        self.max_retries = 3
    
    def __str__(self) -> str:
        """String representation with context information."""
        parts = [f"{self.__class__.__name__}: {self.message}"]
        
        if self.context.component:
            parts.append(f"Component: {self.context.component}")
        
        if self.context.operation:
            parts.append(f"Operation: {self.context.operation}")
        
        if self.context.file_path:
            parts.append(f"File: {self.context.file_path}")
        
        if self.cause:
            parts.append(f"Caused by: {self.cause}")
        
        return " | ".join(parts)
    
    def can_retry(self) -> bool:
        """Check if this error can be retried."""
        return (
            self.recovery_strategy == RecoveryStrategy.RETRY and
            self.retry_count < self.max_retries
        )
    
    def increment_retry(self) -> None:
        """Increment retry counter."""
        self.retry_count += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for serialization."""
        return {
            'error_type': self.__class__.__name__,
            'message': self.message,
            'category': self.category.name,
            'severity': self.severity.value,
            'recovery_strategy': self.recovery_strategy.value,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries,
            'context': {
                'error_id': str(self.context.error_id),
                'timestamp': self.context.timestamp.isoformat(),
                'component': self.context.component,
                'operation': self.context.operation,
                'file_path': str(self.context.file_path) if self.context.file_path else None,
                'line_number': self.context.line_number,
                'correlation_id': str(self.context.correlation_id) if self.context.correlation_id else None,
            },
            'cause': str(self.cause) if self.cause else None,
            'suggestions': self.suggestions,
        }


# ============================================================================
# Specific Error Types
# ============================================================================

class FileError(NetStealthError):
    """Base class for file-related errors."""
    
    def __init__(
        self,
        message: str,
        file_path: Optional[Path] = None,
        category: ErrorCategory = ErrorCategory.FILE_NOT_FOUND,
        **kwargs
    ):
        context = kwargs.get('context', ErrorContext())
        if file_path:
            context = ErrorContext(
                error_id=context.error_id,
                timestamp=context.timestamp,
                component=context.component,
                operation=context.operation,
                file_path=file_path,
                line_number=context.line_number,
                user_data=context.user_data,
                system_info=context.system_info,
                correlation_id=context.correlation_id
            )
        
        super().__init__(
            message=message,
            category=category,
            context=context,
            **kwargs
        )
        self.file_path = file_path


class FileNotFoundError(FileError):
    """File or resource not found."""
    
    def __init__(self, file_path: Path, **kwargs):
        super().__init__(
            message=f"File not found: {file_path}",
            file_path=file_path,
            category=ErrorCategory.FILE_NOT_FOUND,
            recovery_strategy=RecoveryStrategy.SKIP,
            suggestions=[
                "Check if the file path is correct",
                "Verify the file exists and is accessible",
                "Check file permissions"
            ],
            **kwargs
        )


class FilePermissionError(FileError):
    """Permission denied accessing file."""
    
    def __init__(self, file_path: Path, operation: str = "access", **kwargs):
        super().__init__(
            message=f"Permission denied: cannot {operation} {file_path}",
            file_path=file_path,
            category=ErrorCategory.FILE_PERMISSION,
            recovery_strategy=RecoveryStrategy.SKIP,
            suggestions=[
                "Check file permissions",
                "Run with appropriate privileges",
                "Verify file ownership"
            ],
            **kwargs
        )


class FileCorruptedError(FileError):
    """File is corrupted or has invalid format."""
    
    def __init__(self, file_path: Path, details: str = "", **kwargs):
        message = f"Corrupted file: {file_path}"
        if details:
            message += f" ({details})"
        
        super().__init__(
            message=message,
            file_path=file_path,
            category=ErrorCategory.FILE_CORRUPTED,
            recovery_strategy=RecoveryStrategy.SKIP,
            suggestions=[
                "Verify file integrity",
                "Re-download or regenerate the file",
                "Check if file format is supported"
            ],
            **kwargs
        )


class ParseError(NetStealthError):
    """Error parsing log files or data."""
    
    def __init__(
        self,
        message: str,
        file_path: Optional[Path] = None,
        line_number: Optional[int] = None,
        **kwargs
    ):
        context = kwargs.get('context', ErrorContext())
        context = ErrorContext(
            error_id=context.error_id,
            timestamp=context.timestamp,
            component=context.component,
            operation=context.operation,
            file_path=file_path or context.file_path,
            line_number=line_number or context.line_number,
            user_data=context.user_data,
            system_info=context.system_info,
            correlation_id=context.correlation_id
        )
        
        super().__init__(
            message=message,
            category=ErrorCategory.PARSE_ERROR,
            recovery_strategy=RecoveryStrategy.PARTIAL,
            context=context,
            suggestions=[
                "Check file format and structure",
                "Verify file encoding",
                "Review parsing configuration"
            ],
            **kwargs
        )


class ValidationError(NetStealthError):
    """Data validation failed."""
    
    def __init__(self, message: str, field: Optional[str] = None, **kwargs):
        if field:
            message = f"Validation failed for '{field}': {message}"
        
        super().__init__(
            message=message,
            category=ErrorCategory.VALIDATION_ERROR,
            recovery_strategy=RecoveryStrategy.SKIP,
            suggestions=[
                "Check input data format",
                "Verify required fields are present",
                "Review validation rules"
            ],
            **kwargs
        )


class ConfigurationError(NetStealthError):
    """Invalid configuration."""
    
    def __init__(self, message: str, config_key: Optional[str] = None, **kwargs):
        if config_key:
            message = f"Configuration error for '{config_key}': {message}"
        
        super().__init__(
            message=message,
            category=ErrorCategory.CONFIGURATION_ERROR,
            severity=ErrorSeverity.HIGH,
            recovery_strategy=RecoveryStrategy.FAIL_FAST,
            suggestions=[
                "Check configuration file syntax",
                "Verify all required settings are present",
                "Review configuration documentation"
            ],
            **kwargs
        )


class DetectionError(NetStealthError):
    """Error in detection logic."""
    
    def __init__(self, message: str, detector_name: Optional[str] = None, **kwargs):
        if detector_name:
            message = f"Detection error in '{detector_name}': {message}"
        
        super().__init__(
            message=message,
            category=ErrorCategory.DETECTION_ERROR,
            recovery_strategy=RecoveryStrategy.PARTIAL,
            suggestions=[
                "Check detector configuration",
                "Verify input data quality",
                "Review detector logic"
            ],
            **kwargs
        )


class PluginError(NetStealthError):
    """Base class for plugin-related errors."""
    
    def __init__(
        self,
        message: str,
        plugin_name: Optional[str] = None,
        category: ErrorCategory = ErrorCategory.PLUGIN_EXECUTION_ERROR,
        **kwargs
    ):
        if plugin_name:
            message = f"Plugin '{plugin_name}': {message}"
        
        super().__init__(
            message=message,
            category=category,
            recovery_strategy=RecoveryStrategy.SKIP,
            **kwargs
        )
        self.plugin_name = plugin_name


class PluginLoadError(PluginError):
    """Failed to load plugin."""
    
    def __init__(self, plugin_name: str, reason: str, **kwargs):
        super().__init__(
            message=f"Failed to load: {reason}",
            plugin_name=plugin_name,
            category=ErrorCategory.PLUGIN_LOAD_ERROR,
            suggestions=[
                "Check plugin file exists",
                "Verify plugin dependencies",
                "Review plugin syntax"
            ],
            **kwargs
        )


class TimeoutError(NetStealthError):
    """Operation timed out."""
    
    def __init__(self, operation: str, timeout_seconds: float, **kwargs):
        super().__init__(
            message=f"Operation '{operation}' timed out after {timeout_seconds}s",
            category=ErrorCategory.TIMEOUT_ERROR,
            recovery_strategy=RecoveryStrategy.RETRY,
            suggestions=[
                "Increase timeout value",
                "Check system performance",
                "Optimize operation if possible"
            ],
            **kwargs
        )


class ResourceError(NetStealthError):
    """System resource unavailable."""
    
    def __init__(self, resource: str, details: str = "", **kwargs):
        message = f"Resource unavailable: {resource}"
        if details:
            message += f" ({details})"
        
        super().__init__(
            message=message,
            category=ErrorCategory.RESOURCE_ERROR,
            severity=ErrorSeverity.HIGH,
            recovery_strategy=RecoveryStrategy.RETRY,
            suggestions=[
                "Check system resources",
                "Free up memory/disk space",
                "Reduce concurrent operations"
            ],
            **kwargs
        )


# ============================================================================
# Error Handler and Recovery System
# ============================================================================

class ErrorHandler:
    """
    Centralized error handling and recovery system.
    
    Provides error logging, recovery strategy execution, and error aggregation.
    """
    
    def __init__(self):
        self.error_history: List[NetStealthError] = []
        self.max_history = 1000
        self.recovery_handlers: Dict[ErrorCategory, Callable] = {}
        self.error_stats = {
            'total_errors': 0,
            'recovered_errors': 0,
            'failed_recoveries': 0,
            'by_category': {},
            'by_severity': {},
        }
    
    def register_recovery_handler(
        self,
        category: ErrorCategory,
        handler: Callable[[NetStealthError], Awaitable[bool]]
    ) -> None:
        """
        Register a recovery handler for specific error category.
        
        Args:
            category: Error category to handle
            handler: Async function that attempts recovery, returns success bool
        """
        self.recovery_handlers[category] = handler
        logger.debug(f"Registered recovery handler for {category}")
    
    async def handle_error(
        self,
        error: Union[NetStealthError, Exception],
        context: Optional[ErrorContext] = None
    ) -> bool:
        """
        Handle an error with appropriate recovery strategy.
        
        Args:
            error: Error to handle
            context: Additional context if error is not NetStealthError
            
        Returns:
            True if error was recovered, False otherwise
        """
        # Convert to NetStealthError if needed
        if not isinstance(error, NetStealthError):
            error = self._convert_to_netstealth_error(error, context)
        
        # Update statistics
        self._update_stats(error)
        
        # Add to history
        self.error_history.append(error)
        if len(self.error_history) > self.max_history:
            self.error_history.pop(0)
        
        # Log the error
        self._log_error(error)
        
        # Attempt recovery
        recovered = await self._attempt_recovery(error)
        
        if recovered:
            self.error_stats['recovered_errors'] += 1
            logger.info(f"Successfully recovered from error: {error.context.error_id}")
        else:
            self.error_stats['failed_recoveries'] += 1
            logger.error(f"Failed to recover from error: {error.context.error_id}")
        
        return recovered
    
    def _convert_to_netstealth_error(
        self,
        error: Exception,
        context: Optional[ErrorContext] = None
    ) -> NetStealthError:
        """Convert generic exception to NetStealthError."""
        error_type = type(error).__name__
        
        # Map common Python exceptions to our categories
        category_mapping = {
            'FileNotFoundError': ErrorCategory.FILE_NOT_FOUND,
            'PermissionError': ErrorCategory.FILE_PERMISSION,
            'ValueError': ErrorCategory.VALIDATION_ERROR,
            'TimeoutError': ErrorCategory.TIMEOUT_ERROR,
            'MemoryError': ErrorCategory.MEMORY_ERROR,
            'ConnectionError': ErrorCategory.NETWORK_ERROR,
            'UnicodeDecodeError': ErrorCategory.ENCODING_ERROR,
        }
        
        category = category_mapping.get(error_type, ErrorCategory.UNKNOWN_ERROR)
        
        return NetStealthError(
            message=str(error),
            category=category,
            context=context or ErrorContext(),
            cause=error
        )
    
    def _update_stats(self, error: NetStealthError) -> None:
        """Update error statistics."""
        self.error_stats['total_errors'] += 1
        
        # By category
        category_name = error.category.name
        self.error_stats['by_category'][category_name] = (
            self.error_stats['by_category'].get(category_name, 0) + 1
        )
        
        # By severity
        severity_name = error.severity.value
        self.error_stats['by_severity'][severity_name] = (
            self.error_stats['by_severity'].get(severity_name, 0) + 1
        )
    
    def _log_error(self, error: NetStealthError) -> None:
        """Log error with appropriate level based on severity."""
        log_message = f"[{error.context.error_id}] {error}"
        
        if error.severity == ErrorSeverity.CRITICAL:
            logger.critical(log_message, exc_info=error.cause)
        elif error.severity == ErrorSeverity.HIGH:
            logger.error(log_message, exc_info=error.cause)
        elif error.severity == ErrorSeverity.MEDIUM:
            logger.warning(log_message)
        else:
            logger.info(log_message)
    
    async def _attempt_recovery(self, error: NetStealthError) -> bool:
        """Attempt to recover from error based on recovery strategy."""
        try:
            # Check if we have a specific recovery handler
            if error.category in self.recovery_handlers:
                handler = self.recovery_handlers[error.category]
                return await handler(error)
            
            # Use default recovery strategies
            if error.recovery_strategy == RecoveryStrategy.FAIL_FAST:
                return False
            
            elif error.recovery_strategy == RecoveryStrategy.RETRY:
                if error.can_retry():
                    error.increment_retry()
                    logger.info(f"Retrying operation (attempt {error.retry_count}/{error.max_retries})")
                    return True
                return False
            
            elif error.recovery_strategy == RecoveryStrategy.SKIP:
                logger.info("Skipping failed operation and continuing")
                return True
            
            elif error.recovery_strategy == RecoveryStrategy.PARTIAL:
                logger.info("Continuing with partial results")
                return True
            
            elif error.recovery_strategy == RecoveryStrategy.FALLBACK:
                logger.info("Using fallback approach")
                return True
            
            elif error.recovery_strategy == RecoveryStrategy.USER_INPUT:
                logger.warning("User intervention required")
                return False
            
            return False
            
        except Exception as recovery_error:
            logger.error(f"Recovery attempt failed: {recovery_error}", exc_info=True)
            return False
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of error statistics."""
        return {
            'stats': self.error_stats.copy(),
            'recent_errors': [
                {
                    'id': str(error.context.error_id),
                    'message': error.message,
                    'category': error.category.name,
                    'severity': error.severity.value,
                    'timestamp': error.context.timestamp.isoformat(),
                }
                for error in self.error_history[-10:]  # Last 10 errors
            ]
        }
    
    def clear_history(self) -> None:
        """Clear error history."""
        self.error_history.clear()
        logger.debug("Error history cleared")


# Global error handler instance
_global_error_handler: Optional[ErrorHandler] = None


def get_error_handler() -> ErrorHandler:
    """Get the global error handler instance."""
    global _global_error_handler
    if _global_error_handler is None:
        _global_error_handler = ErrorHandler()
    return _global_error_handler


def set_error_handler(error_handler: ErrorHandler) -> None:
    """Set the global error handler instance."""
    global _global_error_handler
    _global_error_handler = error_handler


# Convenience functions
async def handle_error(
    error: Union[NetStealthError, Exception],
    context: Optional[ErrorContext] = None
) -> bool:
    """Handle an error using the global error handler."""
    return await get_error_handler().handle_error(error, context)


def create_error_context(
    component: str,
    operation: str,
    file_path: Optional[Path] = None,
    **kwargs
) -> ErrorContext:
    """Create an error context with common fields."""
    return ErrorContext(
        component=component,
        operation=operation,
        file_path=file_path,
        **kwargs
    )


# Export public API
__all__ = [
    # Enums
    'ErrorSeverity',
    'ErrorCategory', 
    'RecoveryStrategy',
    
    # Core classes
    'ErrorContext',
    'NetStealthError',
    'ErrorHandler',
    
    # Specific error types
    'FileError',
    'FileNotFoundError',
    'FilePermissionError',
    'FileCorruptedError',
    'ParseError',
    'ValidationError',
    'ConfigurationError',
    'DetectionError',
    'PluginError',
    'PluginLoadError',
    'TimeoutError',
    'ResourceError',
    
    # Global functions
    'get_error_handler',
    'set_error_handler',
    'handle_error',
    'create_error_context',
]
