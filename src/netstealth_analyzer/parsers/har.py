"""
Async HAR (HTTP Archive) file parser for NetStealth Analyzer.

This module parses HAR files to extract HTTP request/response data,
timing information, and detect stealth-related issues with full async support.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Union
from urllib.parse import urlparse

from .base import BaseLogParser, ParseResult
from ..models.enums import LogFormat, NetworkProtocol
from ..models.network import NetworkTrace, HttpTrace, HttpRequest, HttpResponse, TimingInfo, HttpData
from ..core.events import EventBus
from .registry import ProtocolParserRegistry


class HarParser(BaseLogParser):
    """Async parser for HAR (HTTP Archive) files."""
    
    def __init__(
        self, 
        event_bus: Optional[EventBus] = None,
        service_domains: Optional[List[str]] = None
    ):
        """
        Initialize HAR parser.
        
        Args:
            event_bus: Optional event bus for progress notifications
            service_domains: List of service domains to analyze
        """
        super().__init__(event_bus, service_domains)
    
    @property
    def supported_format(self) -> LogFormat:
        """Get the log format this parser supports."""
        return LogFormat.HAR
    
    @property
    def file_extensions(self) -> List[str]:
        """Get supported file extensions."""
        return ['.har', '.json']
    
    async def parse(
        self, 
        file_path: Union[str, Path],
        **kwargs
    ) -> ParseResult:
        """
        Parse HAR file asynchronously.
        
        Args:
            file_path: Path to HAR file
            **kwargs: Additional options (unused for HAR)
            
        Returns:
            ParseResult containing parsed network traces
            
        Raises:
            ValueError: If HAR file format is invalid
            FileNotFoundError: If file doesn't exist
            PermissionError: If file can't be read
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"HAR file not found: {path}")
        
        self._emit_progress("har_parse_started", {"file": str(path)})
        
        try:
            # Read HAR file content
            content = await self._read_file_async(path)
            har_data = json.loads(content)
            
            # Validate HAR structure
            if 'log' not in har_data:
                raise ValueError("Invalid HAR file: missing 'log' section")
            
            log_data = har_data['log']
            entries = log_data.get('entries', [])
            
            # Parse metadata
            metadata = {
                'har_version': log_data.get('version', '1.2'),
                'creator': log_data.get('creator', {}),
                'browser': log_data.get('browser', {}),
                'pages': log_data.get('pages', []),
                'entry_count': len(entries),
            }
            
            # Parse entries into network traces
            network_traces = []
            statistics = self._init_statistics()
            errors = []
            
            for index, entry in enumerate(entries):
                try:
                    trace = await self._parse_har_entry(entry, index)
                    if trace:
                        network_traces.append(trace)
                        self._update_statistics(statistics, trace)
                        
                        # Emit progress for every 100 entries
                        if (index + 1) % 100 == 0:
                            self._emit_progress("har_entries_processed", {
                                "processed": index + 1,
                                "total": len(entries)
                            })
                            
                except Exception as e:
                    error = {
                        'entry_index': index,
                        'error': str(e),
                        'type': 'entry_parse_error'
                    }
                    errors.append(error)
            
            # Finalize statistics
            self._finalize_statistics(statistics, network_traces)
            
            result = ParseResult(
                format=LogFormat.HAR,
                source_file=str(path),
                metadata=metadata,
                network_traces=network_traces,
                statistics=statistics,
                errors=errors
            )
            
            self._emit_progress("har_parse_completed", {
                "traces": len(network_traces),
                "errors": len(errors)
            })
            
            return result
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in HAR file: {e}")
        except Exception as e:
            self._emit_progress("har_parse_failed", {"error": str(e)})
            raise
    
    async def stream_parse(
        self, 
        file_path: Union[str, Path],
        **kwargs
    ) -> AsyncIterator[NetworkTrace]:
        """
        Parse HAR file and yield traces as they're processed.
        
        Args:
            file_path: Path to HAR file
            **kwargs: Additional options (unused for HAR)
            
        Yields:
            NetworkTrace objects as they're parsed
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"HAR file not found: {path}")
        
        self._emit_progress("har_stream_started", {"file": str(path)})
        
        try:
            # Read HAR file content
            content = await self._read_file_async(path)
            har_data = json.loads(content)
            
            # Validate HAR structure
            if 'log' not in har_data:
                raise ValueError("Invalid HAR file: missing 'log' section")
            
            log_data = har_data['log']
            entries = log_data.get('entries', [])
            
            # Stream parse entries
            for index, entry in enumerate(entries):
                try:
                    trace = await self._parse_har_entry(entry, index)
                    if trace:
                        yield trace
                        
                        # Emit progress for every 50 entries
                        if (index + 1) % 50 == 0:
                            self._emit_progress("har_stream_progress", {
                                "processed": index + 1,
                                "total": len(entries)
                            })
                            
                except Exception as e:
                    # Log error but continue processing
                    self._emit_progress("har_entry_error", {
                        "entry_index": index,
                        "error": str(e)
                    })
                    continue
            
            self._emit_progress("har_stream_completed", {"total": len(entries)})
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in HAR file: {e}")
    
    async def _validate_format(self, file_path: Path) -> bool:
        """
        Validate HAR file format.
        
        Args:
            file_path: Path to HAR file
            
        Returns:
            True if file is a valid HAR file
        """
        try:
            # Read first part of file to check structure
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read first 1KB to check basic structure
                sample = f.read(1024)
                
            # Try to parse as JSON and check for HAR structure
            try:
                data = json.loads(sample + '}}')  # Add closing braces in case truncated
            except json.JSONDecodeError:
                # If sample is truncated, try reading more
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read(10240)  # Read first 10KB
                try:
                    data = json.loads(content)
                except json.JSONDecodeError:
                    return False
            
            # Check for HAR structure
            return 'log' in data and isinstance(data.get('log'), dict)
            
        except Exception:
            return False
    
    async def _parse_har_entry(self, entry: Dict[str, Any], index: int) -> Optional[NetworkTrace]:
        """
        Parse individual HAR entry into NetworkTrace.
        
        Args:
            entry: HAR entry data
            index: Entry index
            
        Returns:
            NetworkTrace object or None if parsing fails
        """
        try:
            request_data = entry.get('request', {})
            response_data = entry.get('response', {})
            timings = entry.get('timings', {})
            
            # Extract basic information
            url = request_data.get('url', '')
            method = request_data.get('method', 'GET')
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Create HTTP request
            request = HttpRequest(
                method=method,
                url=url,
                headers=self._normalize_headers(request_data.get('headers', [])),
                body=self._extract_request_body(request_data.get('postData', {})),
                timestamp=self._parse_timestamp(entry.get('startedDateTime')),
            )
            
            # Create HTTP response
            response = HttpResponse(
                status_code=response_data.get('status', 0),
                status_text=response_data.get('statusText', ''),
                headers=self._normalize_headers(response_data.get('headers', [])),
                body=self._extract_response_body(response_data.get('content', {})),
                body_size=response_data.get('bodySize', 0),
            )
            
            # Create timing info
            timing = TimingInfo(
                dns_lookup=timings.get('dns', -1),
                tcp_connect=timings.get('connect', -1),
                ssl_handshake=timings.get('ssl', -1),
                request_sent=timings.get('send', -1),
                waiting=timings.get('wait', -1),
                content_download=timings.get('receive', -1),
                blocked=timings.get('blocked', -1),
            )
            
            # Create HttpData for protocol-specific data
            http_data = HttpData(
                request=request,
                response=response,
                timing=timing
            )
            
            # Create NetworkTrace with protocol-specific data
            trace = NetworkTrace(
                trace_id=f"har_{index}",
                protocol=NetworkProtocol.HTTP,
                protocol_data=http_data,  # Use protocol_data for new architecture
                metadata={
                    'source_format': LogFormat.HAR.value,
                    'entry_index': index,
                    'domain': domain,
                    'is_service': self._is_service_domain(domain),
                    'is_ip_detection': self._is_ip_detection_service(domain),
                    'is_oauth': self._is_oauth_related(url),
                    'is_secure': parsed_url.scheme == 'https',
                    'has_proxy_headers': (
                        self._has_proxy_headers(request.headers) or 
                        self._has_proxy_headers(response.headers)
                    ),
                    'timestamp': request.timestamp.isoformat() if request.timestamp else None,
                    # Add backward compatibility for tests
                    'http_request': {
                        'method': request.method,
                        'url': request.url,
                        'headers': request.headers,
                        'body': request.body
                    },
                    'http_response': {
                        'status_code': response.status_code,
                        'status_text': response.status_text,
                        'headers': response.headers,
                        'body': response.body,
                        'body_size': response.body_size
                    },
                    'http_timing': {
                        'dns_lookup': timing.dns_lookup,
                        'tcp_connect': timing.tcp_connect,
                        'ssl_handshake': timing.ssl_handshake,
                        'request_sent': timing.request_sent,
                        'waiting': timing.waiting,
                        'content_download': timing.content_download,
                        'blocked': timing.blocked,
                        'total_time': (timing.dns_lookup + timing.tcp_connect + 
                                     timing.ssl_handshake + timing.request_sent + 
                                     timing.waiting + timing.content_download)
                    }
                }
            )
            
            return trace
            
        except Exception as e:
            # Return None for failed entries, let caller handle error logging
            return None
    
    def _extract_request_body(self, post_data: Dict[str, Any]) -> Optional[str]:
        """Extract request body from HAR postData."""
        if not post_data:
            return None
        
        # Try to get text content
        text = post_data.get('text')
        if text:
            return text
        
        # Try to reconstruct from params
        params = post_data.get('params', [])
        if params:
            param_pairs = []
            for param in params:
                name = param.get('name', '')
                value = param.get('value', '')
                param_pairs.append(f"{name}={value}")
            return "&".join(param_pairs)
        
        return None
    
    def _extract_response_body(self, content: Dict[str, Any]) -> Optional[str]:
        """Extract response body from HAR content."""
        if not content:
            return None
        
        text = content.get('text')
        if text:
            return text
        
        return None
    
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse HAR timestamp string."""
        if not timestamp_str:
            return None
        
        try:
            # HAR timestamps are in ISO 8601 format
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return None
    
    def _init_statistics(self) -> Dict[str, Any]:
        """Initialize statistics dictionary."""
        return {
            'total_requests': 0,
            'successful_responses': 0,
            'service_requests': 0,
            'proxy_indicators': 0,
            'ip_detection_requests': 0,
            'oauth_requests': 0,
            'secure_requests': 0,
            'insecure_requests': 0,
            'unique_domains': set(),
            'response_times': [],
            'ssl_times': [],
            'client_errors': 0,
            'server_errors': 0,
        }
    
    def _update_statistics(self, stats: Dict[str, Any], trace: NetworkTrace) -> None:
        """Update statistics with trace data."""
        stats['total_requests'] += 1
        
        # Response status from metadata
        metadata = trace.metadata or {}
        http_response = metadata.get('http_response', {})
        status_code = http_response.get('status_code', 0)
        
        if 200 <= status_code < 300:
            stats['successful_responses'] += 1
        elif 400 <= status_code < 500:
            stats['client_errors'] += 1
        elif 500 <= status_code < 600:
            stats['server_errors'] += 1
        
        # Service and security flags
        if metadata.get('is_service'):
            stats['service_requests'] += 1
        if metadata.get('has_proxy_headers'):
            stats['proxy_indicators'] += 1
        if metadata.get('is_ip_detection'):
            stats['ip_detection_requests'] += 1
        if metadata.get('is_oauth'):
            stats['oauth_requests'] += 1
        if metadata.get('is_secure'):
            stats['secure_requests'] += 1
        else:
            stats['insecure_requests'] += 1
        
        # Domain tracking
        domain = metadata.get('domain')
        if domain:
            stats['unique_domains'].add(domain)
        
        # Timing data from metadata
        http_timing = metadata.get('http_timing', {})
        total_time = http_timing.get('total_time', 0)
        if total_time > 0:
            stats['response_times'].append(total_time)
        
        ssl_handshake = http_timing.get('ssl_handshake', 0)
        if ssl_handshake > 0:
            stats['ssl_times'].append(ssl_handshake)
    
    def _finalize_statistics(self, stats: Dict[str, Any], traces: List[NetworkTrace]) -> None:
        """Finalize statistics calculations."""
        # Convert sets to counts
        stats['unique_domains'] = len(stats['unique_domains'])
        
        # Calculate rates
        total = stats['total_requests']
        if total > 0:
            stats['success_rate'] = (stats['successful_responses'] / total) * 100
            stats['proxy_detection_risk'] = (stats['proxy_indicators'] / total) * 100
        else:
            stats['success_rate'] = 0
            stats['proxy_detection_risk'] = 0
        
        # Calculate timing averages
        response_times = stats['response_times']
        if response_times:
            stats['average_response_time'] = sum(response_times) / len(response_times)
            stats['max_response_time'] = max(response_times)
            stats['min_response_time'] = min(response_times)
        else:
            stats['average_response_time'] = 0
            stats['max_response_time'] = 0
            stats['min_response_time'] = 0
        
        ssl_times = stats['ssl_times']
        if ssl_times:
            stats['average_ssl_time'] = sum(ssl_times) / len(ssl_times)
            stats['max_ssl_time'] = max(ssl_times)
        else:
            stats['average_ssl_time'] = 0
            stats['max_ssl_time'] = 0
        
        # Remove raw timing lists to save memory
        del stats['response_times']
        del stats['ssl_times']
