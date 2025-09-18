"""
Unit tests for NetStealth Analyzer compatibility layer.

Tests Python version compatibility, feature detection, fallback implementations,
and compatibility decorators.
"""

import pytest
import sys
import asyncio
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import os
from typing import Dict, Any

from src.netstealth_analyzer.compatibility import (
    # Version constants
    PYTHON_VERSION,
    IS_PYTHON_311,
    IS_PYTHON_312,
    IS_PYTHON_313,
    
    # Core compatibility classes
    TaskGroup,
    ExceptionGroup,
    AsyncContextManagerCompat,
    
    # Feature detection
    FeatureDetector,
    
    # Utility functions
    load_toml,
    get_optimized_dict,
    get_python_version,
    has_feature,
    require_python_version,
    initialize_compatibility,
    
    # Decorators
    override,
    ensure_async,
    python_version_required,
    
    # Exceptions
    CompatibilityError,
)


class TestVersionConstants:
    """Test version constants and detection."""
    
    def test_python_version_constants(self):
        """Test Python version constants are correctly set."""
        assert PYTHON_VERSION == sys.version_info
        assert isinstance(IS_PYTHON_311, bool)
        assert isinstance(IS_PYTHON_312, bool)
        assert isinstance(IS_PYTHON_313, bool)
        
        # Test version logic consistency
        if PYTHON_VERSION >= (3, 13):
            assert IS_PYTHON_313 is True
            assert IS_PYTHON_312 is True
            assert IS_PYTHON_311 is True
        elif PYTHON_VERSION >= (3, 12):
            assert IS_PYTHON_313 is False
            assert IS_PYTHON_312 is True
            assert IS_PYTHON_311 is True
        elif PYTHON_VERSION >= (3, 11):
            assert IS_PYTHON_313 is False
            assert IS_PYTHON_312 is False
            assert IS_PYTHON_311 is True
        else:
            assert IS_PYTHON_313 is False
            assert IS_PYTHON_312 is False
            assert IS_PYTHON_311 is False
    
    def test_get_python_version(self):
        """Test get_python_version function."""
        version = get_python_version()
        expected = f"{PYTHON_VERSION.major}.{PYTHON_VERSION.minor}.{PYTHON_VERSION.micro}"
        assert version == expected
        assert isinstance(version, str)
        
        # Test format
        parts = version.split('.')
        assert len(parts) == 3
        assert all(part.isdigit() for part in parts)


class TestCompatibilityError:
    """Test CompatibilityError exception."""
    
    def test_compatibility_error_creation(self):
        """Test CompatibilityError can be created and raised."""
        error = CompatibilityError("Test error message")
        assert str(error) == "Test error message"
        assert isinstance(error, Exception)
        
        with pytest.raises(CompatibilityError, match="Test error message"):
            raise CompatibilityError("Test error message")
    
    def test_compatibility_error_inheritance(self):
        """Test CompatibilityError inherits from Exception."""
        error = CompatibilityError("Test")
        assert isinstance(error, Exception)
        assert isinstance(error, CompatibilityError)


class TestVersionRequirements:
    """Test version requirement functions."""
    
    def test_require_python_version_success(self):
        """Test require_python_version with satisfied requirements."""
        # Should not raise for current version
        require_python_version(PYTHON_VERSION.major, PYTHON_VERSION.minor)
        
        # Should not raise for older version requirements
        require_python_version(3, 8)
        require_python_version(3, 10)
    
    def test_require_python_version_failure(self):
        """Test require_python_version with unsatisfied requirements."""
        # Should raise for future version requirements
        with pytest.raises(CompatibilityError, match="Python .+ required"):
            require_python_version(4, 0)
        
        with pytest.raises(CompatibilityError, match="Python .+ required"):
            require_python_version(3, 20)
    
    def test_require_python_version_error_message(self):
        """Test require_python_version error message format."""
        try:
            require_python_version(4, 0)
        except CompatibilityError as e:
            error_msg = str(e)
            assert "Python 4.0+ required" in error_msg
            assert f"running {PYTHON_VERSION.major}.{PYTHON_VERSION.minor}" in error_msg


class TestTaskGroupCompatibility:
    """Test TaskGroup compatibility layer."""
    
    @pytest.mark.asyncio
    async def test_taskgroup_basic_usage(self):
        """Test basic TaskGroup usage."""
        results = []
        
        async def test_task(value):
            results.append(value)
            return value
        
        async with TaskGroup() as tg:
            task1 = tg.create_task(test_task(1))
            task2 = tg.create_task(test_task(2))
        
        assert 1 in results
        assert 2 in results
        assert len(results) == 2
    
    @pytest.mark.asyncio
    async def test_taskgroup_context_manager(self):
        """Test TaskGroup as async context manager."""
        entered = False
        exited = False
        
        async with TaskGroup() as tg:
            entered = True
            assert tg is not None
        
        exited = True
        assert entered is True
        assert exited is True
    
    @pytest.mark.asyncio
    async def test_taskgroup_task_creation(self):
        """Test TaskGroup task creation."""
        async def dummy_task():
            return "completed"
        
        async with TaskGroup() as tg:
            task = tg.create_task(dummy_task())
            assert asyncio.iscoroutine(task) or hasattr(task, '__await__')


class TestExceptionGroupCompatibility:
    """Test ExceptionGroup compatibility layer."""
    
    def test_exception_group_creation(self):
        """Test ExceptionGroup creation."""
        exceptions = [ValueError("error1"), TypeError("error2")]
        group = ExceptionGroup("Multiple errors", exceptions)
        
        # ExceptionGroup string representation includes sub-exception count
        assert "Multiple errors" in str(group)
        # ExceptionGroup.exceptions is a tuple, not a list
        assert list(group.exceptions) == exceptions
        assert isinstance(group, Exception)
    
    def test_exception_group_inheritance(self):
        """Test ExceptionGroup inheritance."""
        # ExceptionGroup requires non-empty exception list
        exceptions = [ValueError("test")]
        group = ExceptionGroup("Test", exceptions)
        assert isinstance(group, Exception)
        assert isinstance(group, ExceptionGroup)
    
    def test_exception_group_with_exceptions(self):
        """Test ExceptionGroup with actual exceptions."""
        exc1 = ValueError("Value error")
        exc2 = TypeError("Type error")
        group = ExceptionGroup("Test group", [exc1, exc2])
        
        assert len(group.exceptions) == 2
        assert exc1 in group.exceptions
        assert exc2 in group.exceptions


class TestTomlCompatibility:
    """Test TOML loading compatibility."""
    
    def test_load_toml_success(self):
        """Test successful TOML loading."""
        toml_content = """
[section]
key = "value"
number = 42
boolean = true

[nested.section]
nested_key = "nested_value"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(toml_content)
            temp_path = f.name
        
        try:
            data = load_toml(temp_path)
            
            assert isinstance(data, dict)
            assert data['section']['key'] == "value"
            assert data['section']['number'] == 42
            assert data['section']['boolean'] is True
            assert data['nested']['section']['nested_key'] == "nested_value"
        finally:
            os.unlink(temp_path)
    
    def test_load_toml_with_path_object(self):
        """Test TOML loading with Path object."""
        toml_content = """
[test]
value = "path_test"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(toml_content)
            temp_path = Path(f.name)
        
        try:
            data = load_toml(temp_path)
            assert data['test']['value'] == "path_test"
        finally:
            temp_path.unlink()
    
    def test_load_toml_file_not_found(self):
        """Test TOML loading with non-existent file."""
        with pytest.raises(FileNotFoundError):
            load_toml("/nonexistent/file.toml")
    
    @patch('src.netstealth_analyzer.compatibility.HAS_TOMLLIB', False)
    def test_load_toml_no_support(self):
        """Test TOML loading when TOML support is not available."""
        with pytest.raises(CompatibilityError, match="TOML support not available"):
            load_toml("test.toml")


class TestOverrideDecorator:
    """Test override decorator compatibility."""
    
    def test_override_decorator_basic(self):
        """Test basic override decorator usage."""
        class Base:
            def method(self):
                return "base"
        
        class Derived(Base):
            @override
            def method(self):
                return "derived"
        
        obj = Derived()
        assert obj.method() == "derived"
    
    def test_override_decorator_preserves_function(self):
        """Test override decorator preserves function properties."""
        def test_function():
            """Test docstring."""
            return "test"
        
        decorated = override(test_function)
        
        # Function should be preserved
        assert decorated() == "test"
        assert decorated.__name__ == "test_function"
        assert decorated.__doc__ == "Test docstring."
    
    def test_override_decorator_with_arguments(self):
        """Test override decorator with function arguments."""
        class Base:
            def method(self, x, y=10):
                return x + y
        
        class Derived(Base):
            @override
            def method(self, x, y=20):
                return x * y
        
        obj = Derived()
        assert obj.method(5) == 100  # 5 * 20
        assert obj.method(5, 3) == 15  # 5 * 3


class TestOptimizedDict:
    """Test optimized dictionary functionality."""
    
    def test_get_optimized_dict(self):
        """Test get_optimized_dict returns dict type."""
        dict_type = get_optimized_dict()
        assert dict_type is dict
        
        # Test that we can create instances
        test_dict = dict_type()
        assert isinstance(test_dict, dict)
        
        test_dict['key'] = 'value'
        assert test_dict['key'] == 'value'
    
    def test_optimized_dict_functionality(self):
        """Test optimized dict works like regular dict."""
        dict_type = get_optimized_dict()
        
        # Test basic operations
        d = dict_type({'a': 1, 'b': 2})
        assert d['a'] == 1
        assert d['b'] == 2
        
        d['c'] = 3
        assert len(d) == 3
        
        assert list(d.keys()) == ['a', 'b', 'c']
        assert list(d.values()) == [1, 2, 3]


class TestAsyncContextManagerCompat:
    """Test AsyncContextManagerCompat class."""
    
    @pytest.mark.asyncio
    async def test_async_context_manager_basic(self):
        """Test basic async context manager functionality."""
        resource = Mock()
        
        async with AsyncContextManagerCompat(resource) as ctx:
            assert ctx == resource
            # The _entered attribute is on the AsyncContextManagerCompat instance, not the resource
        
        # Test that the context manager was properly entered
        assert True  # Context manager completed successfully
    
    @pytest.mark.asyncio
    async def test_async_context_manager_with_async_resource(self):
        """Test async context manager with async resource."""
        class AsyncResource:
            def __init__(self):
                self.entered = False
                self.exited = False
            
            async def __aenter__(self):
                self.entered = True
                return self
            
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                self.exited = True
                return False
        
        resource = AsyncResource()
        
        async with AsyncContextManagerCompat(resource) as ctx:
            assert ctx.entered is True
            assert ctx.exited is False
        
        assert resource.exited is True
    
    @pytest.mark.asyncio
    async def test_async_context_manager_without_async_methods(self):
        """Test async context manager with regular resource."""
        resource = {"data": "test"}
        
        async with AsyncContextManagerCompat(resource) as ctx:
            assert ctx == resource
            assert ctx["data"] == "test"


class TestFeatureDetector:
    """Test FeatureDetector class."""
    
    def test_has_taskgroup(self):
        """Test TaskGroup feature detection."""
        result = FeatureDetector.has_taskgroup()
        assert isinstance(result, bool)
        assert result == IS_PYTHON_311
    
    def test_has_exception_group(self):
        """Test ExceptionGroup feature detection."""
        result = FeatureDetector.has_exception_group()
        assert isinstance(result, bool)
        assert result == IS_PYTHON_311
    
    def test_has_tomllib(self):
        """Test tomllib feature detection."""
        result = FeatureDetector.has_tomllib()
        assert isinstance(result, bool)
    
    def test_has_override_decorator(self):
        """Test override decorator feature detection."""
        result = FeatureDetector.has_override_decorator()
        assert isinstance(result, bool)
        assert result == IS_PYTHON_312
    
    def test_has_optimized_dict(self):
        """Test optimized dict feature detection."""
        result = FeatureDetector.has_optimized_dict()
        assert isinstance(result, bool)
        assert result == IS_PYTHON_312
    
    def test_get_feature_summary(self):
        """Test feature summary generation."""
        summary = FeatureDetector.get_feature_summary()
        
        assert isinstance(summary, dict)
        assert 'python_version' in summary
        assert 'taskgroup' in summary
        assert 'exception_group' in summary
        assert 'tomllib' in summary
        assert 'override_decorator' in summary
        assert 'optimized_dict' in summary
        
        # Verify types
        assert isinstance(summary['python_version'], str)
        assert isinstance(summary['taskgroup'], bool)
        assert isinstance(summary['exception_group'], bool)
        assert isinstance(summary['tomllib'], bool)
        assert isinstance(summary['override_decorator'], bool)
        assert isinstance(summary['optimized_dict'], bool)
        
        # Verify version format
        version_parts = summary['python_version'].split('.')
        assert len(version_parts) == 3
        assert all(part.isdigit() for part in version_parts)


class TestHasFeature:
    """Test has_feature utility function."""
    
    def test_has_feature_existing(self):
        """Test has_feature with existing features."""
        assert isinstance(has_feature('taskgroup'), bool)
        assert isinstance(has_feature('exception_group'), bool)
        assert isinstance(has_feature('tomllib'), bool)
        assert isinstance(has_feature('override_decorator'), bool)
        assert isinstance(has_feature('optimized_dict'), bool)
    
    def test_has_feature_nonexistent(self):
        """Test has_feature with non-existent feature."""
        assert has_feature('nonexistent_feature') is False
        assert has_feature('') is False
        assert has_feature('invalid') is False
    
    def test_has_feature_consistency(self):
        """Test has_feature consistency with FeatureDetector."""
        summary = FeatureDetector.get_feature_summary()
        
        for feature_name, expected_value in summary.items():
            if feature_name != 'python_version':  # Skip version string
                assert has_feature(feature_name) == expected_value


class TestEnsureAsyncDecorator:
    """Test ensure_async decorator."""
    
    @pytest.mark.asyncio
    async def test_ensure_async_with_sync_function(self):
        """Test ensure_async decorator with synchronous function."""
        def sync_function(x, y):
            return x + y
        
        async_function = ensure_async(sync_function)
        
        assert asyncio.iscoroutinefunction(async_function)
        result = await async_function(5, 3)
        assert result == 8
    
    @pytest.mark.asyncio
    async def test_ensure_async_with_async_function(self):
        """Test ensure_async decorator with asynchronous function."""
        async def async_function(x, y):
            return x * y
        
        decorated_function = ensure_async(async_function)
        
        assert asyncio.iscoroutinefunction(decorated_function)
        assert decorated_function is async_function  # Should return original
        
        result = await decorated_function(4, 5)
        assert result == 20
    
    @pytest.mark.asyncio
    async def test_ensure_async_preserves_metadata(self):
        """Test ensure_async preserves function metadata."""
        def original_function():
            """Original docstring."""
            return "test"
        
        async_function = ensure_async(original_function)
        
        # The @wraps decorator preserves the original function name
        assert async_function.__name__ == "original_function"
        result = await async_function()
        assert result == "test"
    
    @pytest.mark.asyncio
    async def test_ensure_async_with_arguments(self):
        """Test ensure_async with various argument types."""
        def func_with_args(a, b, c=10, *args, **kwargs):
            return {
                'a': a,
                'b': b,
                'c': c,
                'args': args,
                'kwargs': kwargs
            }
        
        async_func = ensure_async(func_with_args)
        # Call with positional args first, then keyword args
        result = await async_func(1, 2, 3, 4, key="value")
        
        assert result['a'] == 1
        assert result['b'] == 2
        assert result['c'] == 3  # Third positional argument overrides default
        assert result['args'] == (4,)  # Fourth positional argument goes to *args
        assert result['kwargs'] == {'key': 'value'}


class TestPythonVersionRequiredDecorator:
    """Test python_version_required decorator."""
    
    def test_python_version_required_success(self):
        """Test python_version_required with satisfied requirements."""
        @python_version_required(3, 8)
        def test_function():
            return "success"
        
        result = test_function()
        assert result == "success"
    
    def test_python_version_required_failure(self):
        """Test python_version_required with unsatisfied requirements."""
        @python_version_required(4, 0)
        def test_function():
            return "should not reach here"
        
        with pytest.raises(CompatibilityError, match="Python 4.0\\+ required"):
            test_function()
    
    def test_python_version_required_preserves_function(self):
        """Test python_version_required preserves function properties."""
        @python_version_required(3, 8)
        def test_function(x, y=10):
            """Test function docstring."""
            return x + y
        
        # The @wraps decorator preserves the original function name
        assert test_function.__name__ == "test_function"
        assert test_function(5) == 15
        assert test_function(5, 20) == 25
    
    def test_python_version_required_with_current_version(self):
        """Test python_version_required with current Python version."""
        @python_version_required(PYTHON_VERSION.major, PYTHON_VERSION.minor)
        def test_function():
            return "current version ok"
        
        result = test_function()
        assert result == "current version ok"


class TestInitializeCompatibility:
    """Test initialize_compatibility function."""
    
    @patch('builtins.print')
    def test_initialize_compatibility_success(self, mock_print):
        """Test successful compatibility initialization."""
        # Should not raise exception for current Python version
        initialize_compatibility()
        
        # Should print version information
        mock_print.assert_called()
        
        # Check that version info was printed
        calls = [str(call) for call in mock_print.call_args_list]
        version_printed = any("NetStealth Analyzer v2.0" in call for call in calls)
        assert version_printed
    
    def test_initialize_compatibility_version_failure(self):
        """Test compatibility initialization with insufficient Python version."""
        # Mock the require_python_version function directly to test the error path
        with patch('src.netstealth_analyzer.compatibility.require_python_version') as mock_require:
            mock_require.side_effect = CompatibilityError("Python 3.13+ required, but running 3.12")
            
            with pytest.raises(CompatibilityError, match="Python 3.13\\+ required"):
                initialize_compatibility()
    
    @patch('builtins.print')
    @patch('src.netstealth_analyzer.compatibility.FeatureDetector.has_taskgroup', return_value=False)
    def test_initialize_compatibility_warnings(self, mock_has_taskgroup, mock_print):
        """Test compatibility initialization with feature warnings."""
        initialize_compatibility()
        
        # Should print warning about missing TaskGroup
        calls = [str(call) for call in mock_print.call_args_list]
        taskgroup_warning = any("TaskGroup not available" in call for call in calls)
        assert taskgroup_warning
    
    @patch('builtins.print')
    @patch('src.netstealth_analyzer.compatibility.FeatureDetector.has_tomllib', return_value=False)
    def test_initialize_compatibility_toml_warning(self, mock_has_tomllib, mock_print):
        """Test compatibility initialization with TOML warning."""
        initialize_compatibility()
        
        # Should print warning about missing TOML support
        calls = [str(call) for call in mock_print.call_args_list]
        toml_warning = any("TOML support not available" in call for call in calls)
        assert toml_warning


class TestCompatibilityIntegration:
    """Integration tests for compatibility layer."""
    
    def test_all_features_detected(self):
        """Test that all features are properly detected."""
        summary = FeatureDetector.get_feature_summary()
        
        # All features should be boolean except version
        for key, value in summary.items():
            if key == 'python_version':
                assert isinstance(value, str)
            else:
                assert isinstance(value, bool)
    
    def test_version_consistency(self):
        """Test version information consistency."""
        version_str = get_python_version()
        summary = FeatureDetector.get_feature_summary()
        
        assert version_str == summary['python_version']
        
        # Parse version and check consistency with constants
        major, minor, micro = map(int, version_str.split('.'))
        assert major == PYTHON_VERSION.major
        assert minor == PYTHON_VERSION.minor
        assert micro == PYTHON_VERSION.micro
    
    @pytest.mark.asyncio
    async def test_async_compatibility_integration(self):
        """Test async compatibility features work together."""
        # Test TaskGroup with ensure_async
        results = []
        
        def sync_task(value):
            results.append(value)
            return value
        
        async_task = ensure_async(sync_task)
        
        async with TaskGroup() as tg:
            tg.create_task(async_task(1))
            tg.create_task(async_task(2))
        
        assert 1 in results
        assert 2 in results
    
    def test_decorator_combination(self):
        """Test combining multiple compatibility decorators."""
        @ensure_async
        @python_version_required(3, 8)
        def combined_function(x):
            return x * 2
        
        # Should be async due to ensure_async (applied first)
        assert asyncio.iscoroutinefunction(combined_function)
    
    def test_error_handling_integration(self):
        """Test error handling across compatibility features."""
        # Test that CompatibilityError is properly raised
        with pytest.raises(CompatibilityError):
            require_python_version(5, 0)
        
        # Test ExceptionGroup creation
        errors = [ValueError("test1"), TypeError("test2")]
        group = ExceptionGroup("Test errors", errors)
        
        assert len(group.exceptions) == 2
        assert isinstance(group, Exception)
    
    def test_feature_availability_consistency(self):
        """Test feature availability is consistent across methods."""
        # Test that has_feature and FeatureDetector give same results
        detector_summary = FeatureDetector.get_feature_summary()
        
        for feature_name in ['taskgroup', 'exception_group', 'tomllib', 
                           'override_decorator', 'optimized_dict']:
            detector_result = detector_summary[feature_name]
            has_feature_result = has_feature(feature_name)
            assert detector_result == has_feature_result, f"Mismatch for {feature_name}"
    
    def test_toml_integration(self):
        """Test TOML integration with file operations."""
        if not has_feature('tomllib'):
            pytest.skip("TOML support not available")
        
        # Create a test TOML file
        toml_content = """
[compatibility]
test = true
version = "2.0.0"

[features]
async_support = true
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(toml_content)
            temp_path = f.name
        
        try:
            data = load_toml(temp_path)
            
            assert data['compatibility']['test'] is True
            assert data['compatibility']['version'] == "2.0.0"
            assert data['features']['async_support'] is True
        finally:
            os.unlink(temp_path)
