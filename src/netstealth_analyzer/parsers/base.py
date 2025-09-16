"""
Base interfaces and classes for log parsers.

This module defines the abstract base class for all log parsers
and common data structures used across the parsing system.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Union

from ..models.enums import LogFormat
from ..models.network import NetworkTrace
from ..core.events import EventBus


@dataclass
class ParseResult:
    """Result of parsing a log file."""
    
    format: LogFormat
    source_file: str
    metadata: Dict[str, Any]
    network_traces: List[NetworkTrace]
    statistics: Dict[str, Any]
    errors: List[Dict[str, Any]]
    
    @property
    def is_successful(self) -> bool:
        """Check if parsing was successful."""
        return len(self.network_traces) > 0 and len(self.errors) == 0
    
    @property
    def trace_count(self) -> int:
        """Get number of network traces parsed."""
        return len(self.network_traces)


class ILogParser(ABC):
    """Abstract base class for all log parsers."""
    
    def __init__(self, event_bus: Optional[EventBus] = None):
        """
        Initialize parser.
        
        Args:
            event_bus: Optional event bus for progress notifications
        """
        self.event_bus = event_bus
    
    @property
    @abstractmethod
    def supported_format(self) -> LogFormat:
        """Get the log format this parser supports."""
        pass
    
    @property
    @abstractmethod
    def file_extensions(self) -> List[str]:
        """Get supported file extensions."""
        pass
    
    @abstractmethod
    async def parse(
        self, 
        file_path: Union[str, Path],
        **kwargs
    ) -> ParseResult:
        """
        Parse a log file asynchronously.
        
        Args:
            file_path: Path to the log file
            **kwargs: Additional parser-specific options
            
        Returns:
            ParseResult containing parsed data
            
        Raises:
            ValueError: If file format is invalid
            FileNotFoundError: If file doesn't exist
            PermissionError: If file can't be read
        """
        pass
    
    @abstractmethod
    async def stream_parse(
        self, 
        file_path: Union[str, Path],
        **kwargs
    ) -> AsyncIterator[NetworkTrace]:
        """
        Parse a log file and yield traces as they're processed.
        
        Args:
            file_path: Path to the log file
            **kwargs: Additional parser-specific options
            
        Yields:
            NetworkTrace objects as they're parsed
            
        Raises:
            ValueError: If file format is invalid
            FileNotFoundError: If file doesn't exist
            PermissionError: If file can't be read
        """
        pass
    
    async def validate_file(self, file_path: Union[str, Path]) -> bool:
        """
        Validate if file can be parsed by this parser.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            True if file is valid for this parser
        """
        path = Path(file_path)
        
        # Check if file exists
        if not path.exists():
            return False
        
        # Check file extension
        if path.suffix.lower() not in self.file_extensions:
            return False
        
        # Perform format-specific validation
        return await self._validate_format(path)
    
    @abstractmethod
    async def _validate_format(self, file_path: Path) -> bool:
        """
        Perform format-specific validation.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            True if file format is valid
        """
        pass
    
    def _emit_progress(self, event_type: str, data: Any = None) -> None:
        """
        Emit progress event if event bus is available.
        
        Args:
            event_type: Type of event
            data: Event data
        """
        if self.event_bus:
            self.event_bus.emit(event_type, data)
    
    async def _read_file_async(self, file_path: Path, encoding: str = 'utf-8') -> str:
        """
        Read file content asynchronously.
        
        Args:
            file_path: Path to file
            encoding: File encoding
            
        Returns:
            File content as string
        """
        import aiofiles
        
        async with aiofiles.open(file_path, 'r', encoding=encoding) as f:
            return await f.read()
    
    async def _read_file_lines_async(
        self, 
        file_path: Path, 
        encoding: str = 'utf-8'
    ) -> AsyncIterator[str]:
        """
        Read file lines asynchronously.
        
        Args:
            file_path: Path to file
            encoding: File encoding
            
        Yields:
            File lines
        """
        import aiofiles
        
        async with aiofiles.open(file_path, 'r', encoding=encoding) as f:
            async for line in f:
                yield line.rstrip('\n\r')


class BaseLogParser(ILogParser):
    """Base implementation with common functionality."""
    
    def __init__(
        self, 
        event_bus: Optional[EventBus] = None,
        service_domains: Optional[List[str]] = None
    ):
        """
        Initialize base parser.
        
        Args:
            event_bus: Optional event bus for progress notifications
            service_domains: List of service domains to analyze
        """
        super().__init__(event_bus)
        self.service_domains = service_domains or []
        
        # Common proxy-revealing headers
        self.proxy_headers = [
            'X-Forwarded-For',
            'X-Real-IP', 
            'Via',
            'X-Proxy-Authorization',
            'Proxy-Authorization',
            'X-Forwarded-Proto',
            'X-Forwarded-Host',
            'X-Forwarded-Server',
            'X-Cluster-Client-IP',
            'CF-Connecting-IP',  # Cloudflare
            'True-Client-IP',    # Akamai
        ]
        
        # IP detection services
        self.ip_services = [
            'httpbin.org',
            'whatismyipaddress.com', 
            'ipinfo.io',
            'iplocation.net',
            'api.ipify.org',
            'checkip.amazonaws.com',
            'icanhazip.com',
            'ifconfig.me',
            'myexternalip.com',
        ]
    
    def _is_service_domain(self, domain: str) -> bool:
        """Check if domain is service-related."""
        if not domain or not self.service_domains:
            return False
        return any(service_domain in domain for service_domain in self.service_domains)
    
    def _is_ip_detection_service(self, domain: str) -> bool:
        """Check if domain is an IP detection service."""
        if not domain:
            return False
        return any(service in domain for service in self.ip_services)
    
    def _has_proxy_headers(self, headers: List[Dict[str, str]]) -> bool:
        """Check if headers contain proxy-revealing information."""
        if not headers:
            return False
        
        header_names = [h.get('name', '').lower() for h in headers]
        return any(proxy_header.lower() in header_names for proxy_header in self.proxy_headers)
    
    def _is_oauth_related(self, url: str) -> bool:
        """Check if URL is OAuth-related."""
        if not url:
            return False
        
        oauth_indicators = ['oauth', 'authorize', 'token', 'auth', 'login', 'sso']
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in oauth_indicators)
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        if not url:
            return ""
        
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return ""
    
    def _normalize_headers(self, headers: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Normalize headers to consistent format."""
        normalized = []
        for header in headers:
            if isinstance(header, dict):
                normalized.append({
                    'name': str(header.get('name', '')),
                    'value': str(header.get('value', '')),
                })
        return normalized
    
    async def _validate_format(self, file_path: Path) -> bool:
        """Default format validation - check if file is readable."""
        try:
            # Try to read first few bytes
            with open(file_path, 'rb') as f:
                f.read(1024)
            return True
        except Exception:
            return False
