"""
Python version compatibility layer for NetStealth Analyzer.

This module provides feature detection and polyfills for different Python versions
(3.11, 3.12, 3.13+) to ensure consistent behavior across supported versions.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import sys
from typing import Any, Dict, Optional, Union, TypeVar, Generic
from functools import wraps
import asyncio
from pathlib import Path

# Version information
PYTHON_VERSION = sys.version_info
IS_PYTHON_311 = PYTHON_VERSION >= (3, 11)
IS_PYTHON_312 = PYTHON_VERSION >= (3, 12)
IS_PYTHON_313 = PYTHON_VERSION >= (3, 13)

# Type variables for generic compatibility
T = TypeVar('T')


class CompatibilityError(Exception):
    """Raised when a required feature is not available in the current Python version."""
    pass


def require_python_version(major: int, minor: int) -> None:
    """
    Ensure the current Python version meets minimum requirements.
    
    Args:
        major: Required major version
        minor: Required minor version
        
    Raises:
        CompatibilityError: If Python version is insufficient
    """
    if PYTHON_VERSION < (major, minor):
        current = f"{PYTHON_VERSION.major}.{PYTHON_VERSION.minor}"
        required = f"{major}.{minor}"
        raise CompatibilityError(
            f"Python {required}+ required, but running {current}"
        )


# ============================================================================
# TaskGroup Compatibility (Python 3.11+)
# ============================================================================

if IS_PYTHON_311:
    from asyncio import TaskGroup
else:
    # Fallback implementation for older versions (should not be needed)
    class TaskGroup:
        """Minimal TaskGroup implementation for compatibility."""
        
        def __init__(self):
            self._tasks = []
            self._errors = []
        
        async def __aenter__(self):
            return self
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            if self._tasks:
                await asyncio.gather(*self._tasks, return_exceptions=True)
            if self._errors:
                raise ExceptionGroup("TaskGroup errors", self._errors)
        
        def create_task(self, coro):
            task = asyncio.create_task(coro)
            self._tasks.append(task)
            return task


# ============================================================================
# ExceptionGroup Compatibility (Python 3.11+)
# ============================================================================

if IS_PYTHON_311:
    from builtins import ExceptionGroup
else:
    # Fallback for older versions
    class ExceptionGroup(Exception):
        """Minimal ExceptionGroup implementation for compatibility."""
        
        def __init__(self, message: str, exceptions: list):
            super().__init__(message)
            self.exceptions = exceptions


# ============================================================================
# Tomllib Compatibility (Python 3.11+)
# ============================================================================

try:
    import tomllib
    HAS_TOMLLIB = True
except ImportError:
    try:
        import tomli as tomllib
        HAS_TOMLLIB = True
    except ImportError:
        tomllib = None
        HAS_TOMLLIB = False


def load_toml(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Load TOML file with compatibility across Python versions.
    
    Args:
        file_path: Path to TOML file
        
    Returns:
        Parsed TOML data
        
    Raises:
        CompatibilityError: If TOML support is not available
    """
    if not HAS_TOMLLIB:
        raise CompatibilityError(
            "TOML support not available. Install 'tomli' package for Python < 3.11"
        )
    
    path = Path(file_path)
    with path.open('rb') as f:
        return tomllib.load(f)


# ============================================================================
# Typing Enhancements (Python 3.12+)
# ============================================================================

if IS_PYTHON_312:
    from typing import override
else:
    # Fallback decorator for older versions
    def override(func):
        """Compatibility decorator for @override (Python 3.12+)."""
        return func


# ============================================================================
# Performance Optimizations (Python 3.12+)
# ============================================================================

def get_optimized_dict() -> type:
    """
    Get the most optimized dictionary type for the current Python version.
    
    Returns:
        Dictionary type optimized for current Python version
    """
    if IS_PYTHON_312:
        # Python 3.12+ has optimized dict implementation
        return dict
    else:
        # Use standard dict for older versions
        return dict


# ============================================================================
# Async Context Manager Enhancements
# ============================================================================

class AsyncContextManagerCompat:
    """Enhanced async context manager with compatibility features."""
    
    def __init__(self, resource: Any):
        self.resource = resource
        self._entered = False
    
    async def __aenter__(self):
        self._entered = True
        if hasattr(self.resource, '__aenter__'):
            return await self.resource.__aenter__()
        return self.resource
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._entered and hasattr(self.resource, '__aexit__'):
            return await self.resource.__aexit__(exc_type, exc_val, exc_tb)
        return False


# ============================================================================
# Feature Detection
# ============================================================================

class FeatureDetector:
    """Detect available features in the current Python environment."""
    
    @staticmethod
    def has_taskgroup() -> bool:
        """Check if TaskGroup is available."""
        return IS_PYTHON_311
    
    @staticmethod
    def has_exception_group() -> bool:
        """Check if ExceptionGroup is available."""
        return IS_PYTHON_311
    
    @staticmethod
    def has_tomllib() -> bool:
        """Check if tomllib is available."""
        return HAS_TOMLLIB
    
    @staticmethod
    def has_override_decorator() -> bool:
        """Check if @override decorator is available."""
        return IS_PYTHON_312
    
    @staticmethod
    def has_optimized_dict() -> bool:
        """Check if optimized dict implementation is available."""
        return IS_PYTHON_312
    
    @staticmethod
    def get_feature_summary() -> Dict[str, bool]:
        """Get summary of all available features."""
        return {
            'python_version': f"{PYTHON_VERSION.major}.{PYTHON_VERSION.minor}.{PYTHON_VERSION.micro}",
            'taskgroup': FeatureDetector.has_taskgroup(),
            'exception_group': FeatureDetector.has_exception_group(),
            'tomllib': FeatureDetector.has_tomllib(),
            'override_decorator': FeatureDetector.has_override_decorator(),
            'optimized_dict': FeatureDetector.has_optimized_dict(),
        }


# ============================================================================
# Compatibility Decorators
# ============================================================================

def ensure_async(func):
    """
    Decorator to ensure a function is async-compatible.
    
    Args:
        func: Function to wrap
        
    Returns:
        Async-compatible function
    """
    if asyncio.iscoroutinefunction(func):
        return func
    
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    
    return async_wrapper


def python_version_required(major: int, minor: int):
    """
    Decorator to mark functions that require specific Python versions.
    
    Args:
        major: Required major version
        minor: Required minor version
        
    Returns:
        Decorator function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            require_python_version(major, minor)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ============================================================================
# Initialization and Validation
# ============================================================================

def get_python_version() -> str:
    """
    Get the current Python version as a string.
    
    Returns:
        Python version string (e.g., "3.13.7")
    """
    return f"{PYTHON_VERSION.major}.{PYTHON_VERSION.minor}.{PYTHON_VERSION.micro}"


def has_feature(feature_name: str) -> bool:
    """
    Check if a specific feature is available.
    
    Args:
        feature_name: Name of the feature to check
        
    Returns:
        True if feature is available
    """
    features = FeatureDetector.get_feature_summary()
    return features.get(feature_name, False)


def initialize_compatibility() -> None:
    """
    Initialize compatibility layer and validate environment.
    
    Raises:
        CompatibilityError: If environment is incompatible
    """
    # Ensure minimum Python version
    require_python_version(3, 11)
    
    # Log feature availability
    features = FeatureDetector.get_feature_summary()
    print(f"NetStealth Analyzer v2.0 - Python {features['python_version']}")
    
    if not features['taskgroup']:
        print("Warning: TaskGroup not available, using fallback implementation")
    
    if not features['tomllib']:
        print("Warning: TOML support not available, install 'tomli' package")


# ============================================================================
# Export Public API
# ============================================================================

__all__ = [
    # Version info
    'PYTHON_VERSION',
    'IS_PYTHON_311',
    'IS_PYTHON_312', 
    'IS_PYTHON_313',
    
    # Core compatibility
    'TaskGroup',
    'ExceptionGroup',
    'override',
    
    # Utilities
    'load_toml',
    'get_optimized_dict',
    'AsyncContextManagerCompat',
    
    # Feature detection
    'FeatureDetector',
    
    # Decorators
    'ensure_async',
    'python_version_required',
    
    # Initialization
    'initialize_compatibility',
    'require_python_version',
    'get_python_version',
    'has_feature',
    
    # Exceptions
    'CompatibilityError',
]


# Initialize on import
if __name__ != '__main__':
    initialize_compatibility()
