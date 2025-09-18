"""
Plugin sandbox for NetStealth Analyzer.

This module provides basic plugin sandboxing capabilities to ensure safe execution
of third-party plugins with resource limits and security constraints.
"""

import asyncio
import logging
import sys
import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, Optional

# Import resource module if available (Unix/Linux only)
try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    resource = None
    HAS_RESOURCE = False

from .base import IPlugin, PluginError, PluginExecutionError

logger = logging.getLogger(__name__)


class PluginSandbox:
    """
    Basic plugin sandbox for safe plugin execution.
    
    Provides resource limits, execution timeouts, and basic security constraints
    for plugin execution. This is a simplified implementation that can be enhanced
    with more advanced sandboxing techniques.
    """
    
    def __init__(
        self,
        max_memory_mb: int = 100,
        max_execution_time: float = 30.0,
        max_cpu_time: float = 10.0,
        allow_network: bool = True,
        allow_file_access: bool = True
    ):
        """
        Initialize plugin sandbox.
        
        Args:
            max_memory_mb: Maximum memory usage in MB
            max_execution_time: Maximum execution time in seconds
            max_cpu_time: Maximum CPU time in seconds
            allow_network: Whether to allow network access
            allow_file_access: Whether to allow file system access
        """
        self.max_memory_mb = max_memory_mb
        self.max_execution_time = max_execution_time
        self.max_cpu_time = max_cpu_time
        self.allow_network = allow_network
        self.allow_file_access = allow_file_access
        
        # Track resource usage
        self._start_time: Optional[float] = None
        self._start_memory: Optional[int] = None
    
    @contextmanager
    def execute_sandboxed(self, plugin: IPlugin):
        """
        Context manager for sandboxed plugin execution.
        
        Args:
            plugin: Plugin to execute in sandbox
            
        Yields:
            None
            
        Raises:
            PluginExecutionError: If execution violates sandbox constraints
        """
        if not plugin.metadata.sandboxed:
            # Plugin doesn't require sandboxing
            yield
            return
        
        logger.debug(f"Executing plugin {plugin.name} in sandbox")
        
        # Set up resource limits
        old_limits = self._setup_resource_limits()
        
        # Set up timeout
        timeout_task = None
        if self.max_execution_time > 0:
            timeout_task = asyncio.create_task(
                self._timeout_handler(self.max_execution_time, plugin.name)
            )
        
        try:
            # Track resource usage
            self._start_monitoring()
            
            yield
            
            # Check resource usage after execution
            self._check_resource_usage(plugin.name)
            
        except asyncio.TimeoutError:
            raise PluginExecutionError(
                f"Plugin {plugin.name} exceeded execution time limit ({self.max_execution_time}s)",
                plugin.name
            )
        except MemoryError:
            raise PluginExecutionError(
                f"Plugin {plugin.name} exceeded memory limit ({self.max_memory_mb}MB)",
                plugin.name
            )
        except Exception as e:
            if isinstance(e, PluginExecutionError):
                raise
            raise PluginExecutionError(
                f"Plugin {plugin.name} execution failed: {e}",
                plugin.name,
                e
            )
        finally:
            # Cancel timeout task
            if timeout_task and not timeout_task.done():
                timeout_task.cancel()
            
            # Restore resource limits
            self._restore_resource_limits(old_limits)
            
            logger.debug(f"Finished executing plugin {plugin.name} in sandbox")
    
    async def execute_plugin_method(
        self,
        plugin: IPlugin,
        method_name: str,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute a plugin method in sandbox.
        
        Args:
            plugin: Plugin instance
            method_name: Name of method to execute
            *args: Positional arguments for the method
            **kwargs: Keyword arguments for the method
            
        Returns:
            Method execution result
            
        Raises:
            PluginExecutionError: If execution fails or violates constraints
        """
        if not hasattr(plugin, method_name):
            raise PluginExecutionError(
                f"Plugin {plugin.name} does not have method {method_name}",
                plugin.name
            )
        
        method = getattr(plugin, method_name)
        
        if not callable(method):
            raise PluginExecutionError(
                f"Plugin {plugin.name} attribute {method_name} is not callable",
                plugin.name
            )
        
        with self.execute_sandboxed(plugin):
            if asyncio.iscoroutinefunction(method):
                return await method(*args, **kwargs)
            else:
                return method(*args, **kwargs)
    
    def _setup_resource_limits(self) -> Dict[str, Any]:
        """Set up resource limits and return old limits."""
        old_limits = {}
        
        try:
            # Memory limit (if supported on platform)
            if HAS_RESOURCE and hasattr(resource, 'RLIMIT_AS') and self.max_memory_mb > 0:
                old_limit = resource.getrlimit(resource.RLIMIT_AS)
                old_limits['memory'] = old_limit
                
                new_limit = self.max_memory_mb * 1024 * 1024  # Convert to bytes
                resource.setrlimit(resource.RLIMIT_AS, (new_limit, old_limit[1]))
            
            # CPU time limit (if supported on platform)
            if HAS_RESOURCE and hasattr(resource, 'RLIMIT_CPU') and self.max_cpu_time > 0:
                old_limit = resource.getrlimit(resource.RLIMIT_CPU)
                old_limits['cpu'] = old_limit
                
                resource.setrlimit(resource.RLIMIT_CPU, (int(self.max_cpu_time), old_limit[1]))
            
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to set resource limits: {e}")
        
        return old_limits
    
    def _restore_resource_limits(self, old_limits: Dict[str, Any]) -> None:
        """Restore previous resource limits."""
        try:
            if HAS_RESOURCE and 'memory' in old_limits and hasattr(resource, 'RLIMIT_AS'):
                resource.setrlimit(resource.RLIMIT_AS, old_limits['memory'])
            
            if HAS_RESOURCE and 'cpu' in old_limits and hasattr(resource, 'RLIMIT_CPU'):
                resource.setrlimit(resource.RLIMIT_CPU, old_limits['cpu'])
                
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to restore resource limits: {e}")
    
    def _start_monitoring(self) -> None:
        """Start monitoring resource usage."""
        self._start_time = time.time()
        
        try:
            # Get current memory usage
            if HAS_RESOURCE and hasattr(resource, 'getrusage'):
                usage = resource.getrusage(resource.RUSAGE_SELF)
                self._start_memory = usage.ru_maxrss
        except Exception:
            self._start_memory = None
    
    def _check_resource_usage(self, plugin_name: str) -> None:
        """Check resource usage after execution."""
        if self._start_time is None:
            return
        
        execution_time = time.time() - self._start_time
        
        # Check execution time
        if self.max_execution_time > 0 and execution_time > self.max_execution_time:
            raise PluginExecutionError(
                f"Plugin {plugin_name} exceeded execution time: {execution_time:.2f}s > {self.max_execution_time}s",
                plugin_name
            )
        
        # Check memory usage (if available)
        if HAS_RESOURCE and self._start_memory is not None and hasattr(resource, 'getrusage'):
            try:
                usage = resource.getrusage(resource.RUSAGE_SELF)
                current_memory = usage.ru_maxrss
                memory_used_mb = (current_memory - self._start_memory) / 1024  # Convert to MB
                
                if self.max_memory_mb > 0 and memory_used_mb > self.max_memory_mb:
                    raise PluginExecutionError(
                        f"Plugin {plugin_name} exceeded memory limit: {memory_used_mb:.2f}MB > {self.max_memory_mb}MB",
                        plugin_name
                    )
            except Exception:
                pass  # Memory monitoring not available
    
    async def _timeout_handler(self, timeout: float, plugin_name: str) -> None:
        """Handle execution timeout."""
        await asyncio.sleep(timeout)
        raise asyncio.TimeoutError(f"Plugin {plugin_name} execution timed out after {timeout}s")
    
    def get_sandbox_config(self) -> Dict[str, Any]:
        """Get current sandbox configuration."""
        return {
            'max_memory_mb': self.max_memory_mb,
            'max_execution_time': self.max_execution_time,
            'max_cpu_time': self.max_cpu_time,
            'allow_network': self.allow_network,
            'allow_file_access': self.allow_file_access
        }


# Global sandbox instance
_global_sandbox: Optional[PluginSandbox] = None


def get_global_sandbox() -> PluginSandbox:
    """Get the global plugin sandbox instance."""
    global _global_sandbox
    if _global_sandbox is None:
        _global_sandbox = PluginSandbox()
    return _global_sandbox


def set_global_sandbox(sandbox: PluginSandbox) -> None:
    """Set the global plugin sandbox instance."""
    global _global_sandbox
    _global_sandbox = sandbox


def reset_global_sandbox() -> None:
    """Reset the global plugin sandbox (mainly for testing)."""
    global _global_sandbox
    _global_sandbox = None


# Convenience functions

async def execute_plugin_safely(
    plugin: IPlugin,
    method_name: str,
    *args,
    sandbox: Optional[PluginSandbox] = None,
    **kwargs
) -> Any:
    """
    Execute a plugin method safely in sandbox.
    
    Args:
        plugin: Plugin instance
        method_name: Name of method to execute
        *args: Positional arguments for the method
        sandbox: Optional sandbox to use (uses global if not provided)
        **kwargs: Keyword arguments for the method
        
    Returns:
        Method execution result
    """
    if sandbox is None:
        sandbox = get_global_sandbox()
    
    return await sandbox.execute_plugin_method(plugin, method_name, *args, **kwargs)


@contextmanager
def sandboxed_execution(plugin: IPlugin, sandbox: Optional[PluginSandbox] = None):
    """
    Context manager for sandboxed plugin execution.
    
    Args:
        plugin: Plugin to execute in sandbox
        sandbox: Optional sandbox to use (uses global if not provided)
    """
    if sandbox is None:
        sandbox = get_global_sandbox()
    
    with sandbox.execute_sandboxed(plugin):
        yield
