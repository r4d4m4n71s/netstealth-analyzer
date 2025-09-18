"""
Async Mitmproxy log parser for NetStealth Analyzer.

This module parses mitmproxy debug logs to extract network connections,
requests, responses, TLS events, and proxy-related information with full async support.
"""

import re
import json
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Union

from .base import BaseLogParser, ParseResult
from ..models.enums import LogFormat
from ..models.network import NetworkTrace, HttpRequest, HttpResponse, TimingInfo
from ..core.events import EventBus


class MitmproxyParser(BaseLogParser):
    """Async parser for mitmproxy debug logs."""
    
    def __init__(
        self, 
        event_bus: Optional[EventBus] = None,
        service_domains: Optional[List[str]] = None
    ):
        """
        Initialize mitmproxy parser.
        
        Args:
            event_bus: Optional event bus for progress notifications
            service_domains: List of service domains to analyze
        """
        super().__init__(event_bus, service_domains)
        
        # Core patterns for log parsing  
        self.patterns = {
            'timestamp': re.compile(r'^\[(\d{2}:\d{2}:\d{2}\.\d{3})\]'),
            'client_connect': re.compile(r'\[([^\]]+)\] client connect'),
            'server_connect': re.compile(r'\[(.*?)\] server connect (.*?) \((.*?)\)'),
            'request': re.compile(r'Request: (GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH) (.+)'),
            'response': re.compile(r'Response: (\d+) (.+)'),
            'tls_hello': re.compile(r'TLS Client Hello: \(\'(.*?)\', (\d+)\)'),
            'tls_error': re.compile(r'TLS.*?error|handshake.*?failed|certificate.*?error', re.IGNORECASE),
            'proxy_error': re.compile(r'(\d+) Forbidden|proxy.*?refused|upstream.*?error', re.IGNORECASE),
            'connection_error': re.compile(r'connection.*?failed|timeout|refused', re.IGNORECASE),
        }
        
        # Service-specific patterns
        self.service_patterns = {
            'oauth_flow': re.compile(r'(authorize|oauth|token)', re.IGNORECASE),
            'datadome': re.compile(r'(captcha-delivery\.com|datadome|x-datadome)', re.IGNORECASE),
            'proxy_headers': re.compile(r'(X-Forwarded-For|X-Real-IP|Via|Proxy)', re.IGNORECASE),
            'ip_detection': re.compile(r'(httpbin\.org/ip|whatismyip|ipinfo\.io|iplocation)', re.IGNORECASE),
        }
    
    @property
    def supported_format(self) -> LogFormat:
        """Get the log format this parser supports."""
        return LogFormat.MITMPROXY
    
    @property
    def file_extensions(self) -> List[str]:
        """Get supported file extensions."""
        return ['.log', '.txt', '.mitm']
    
    async def parse(
        self, 
        file_path: Union[str, Path],
        **kwargs
    ) -> ParseResult:
        """
        Parse mitmproxy log file asynchronously.
        
        Args:
            file_path: Path to mitmproxy log file
            **kwargs: Additional options (unused for mitmproxy)
            
        Returns:
            ParseResult containing parsed network traces
            
        Raises:
            ValueError: If log file format is invalid
            FileNotFoundError: If file doesn't exist
            PermissionError: If file can't be read
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Mitmproxy log file not found: {path}")
        
        self._emit_progress("mitmproxy_parse_started", {"file": str(path)})
        
        try:
            # Parse log file line by line
            network_traces = []
            statistics = self._init_statistics()
            errors = []
            context = {}
            line_count = 0
            
            async for line_num, line in self._read_file_lines_with_numbers(path):
                line_count += 1
                
                if not line.strip():
                    continue
                
                try:
                    # Parse line and potentially create network trace
                    trace = await self._parse_log_line(line, line_num, context)
                    if trace:
                        network_traces.append(trace)
                        self._update_statistics(statistics, trace)
                    
                    # Emit progress for every 1000 lines
                    if line_count % 1000 == 0:
                        self._emit_progress("mitmproxy_lines_processed", {
                            "processed": line_count
                        })
                        
                except Exception as e:
                    error = {
                        'line_number': line_num,
                        'line_content': line[:200],  # Truncate long lines
                        'error': str(e),
                        'type': 'line_parse_error'
                    }
                    errors.append(error)
            
            # Create metadata
            metadata = {
                'line_count': line_count,
                'parser_version': '2.0',
                'context_entries': len(context),
            }
            
            # Finalize statistics
            self._finalize_statistics(statistics, network_traces)
            
            result = ParseResult(
                format=LogFormat.MITMPROXY,
                source_file=str(path),
                metadata=metadata,
                network_traces=network_traces,
                statistics=statistics,
                errors=errors
            )
            
            self._emit_progress("mitmproxy_parse_completed", {
                "traces": len(network_traces),
                "errors": len(errors),
                "lines": line_count
            })
            
            return result
            
        except Exception as e:
            self._emit_progress("mitmproxy_parse_failed", {"error": str(e)})
            raise
    
    async def stream_parse(
        self, 
        file_path: Union[str, Path],
        **kwargs
    ) -> AsyncIterator[NetworkTrace]:
        """
        Parse mitmproxy log file and yield traces as they're processed.
        
        Args:
            file_path: Path to mitmproxy log file
            **kwargs: Additional options (unused for mitmproxy)
            
        Yields:
            NetworkTrace objects as they're parsed
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Mitmproxy log file not found: {path}")
        
        self._emit_progress("mitmproxy_stream_started", {"file": str(path)})
        
        try:
            context = {}
            line_count = 0
            
            async for line_num, line in self._read_file_lines_with_numbers(path):
                line_count += 1
                
                if not line.strip():
                    continue
                
                try:
                    trace = await self._parse_log_line(line, line_num, context)
                    if trace:
                        yield trace
                        
                        # Emit progress for every 500 lines
                        if line_count % 500 == 0:
                            self._emit_progress("mitmproxy_stream_progress", {
                                "processed": line_count
                            })
                            
                except Exception as e:
                    # Log error but continue processing
                    self._emit_progress("mitmproxy_line_error", {
                        "line_number": line_num,
                        "error": str(e)
                    })
                    continue
            
            self._emit_progress("mitmproxy_stream_completed", {"lines": line_count})
            
        except Exception as e:
            self._emit_progress("mitmproxy_stream_failed", {"error": str(e)})
            raise
    
    async def _validate_format(self, file_path: Path) -> bool:
        """
        Validate mitmproxy log file format.
        
        Args:
            file_path: Path to log file
            
        Returns:
            True if file appears to be a mitmproxy log
        """
        try:
            # Read first few lines to check for mitmproxy patterns
            line_count = 0
            mitmproxy_indicators = 0
            
            async for line in self._read_file_lines_async(file_path):
                line_count += 1
                
                # Check for mitmproxy-specific patterns
                if any(pattern.search(line) for pattern in self.patterns.values()):
                    mitmproxy_indicators += 1
                
                # Check first 50 lines
                if line_count >= 50:
                    break
            
            # Consider valid if we found mitmproxy patterns in at least 10% of lines
            return line_count > 0 and (mitmproxy_indicators / line_count) >= 0.1
            
        except Exception:
            return False
    
    async def _read_file_lines_with_numbers(
        self, 
        file_path: Path, 
        encoding: str = 'utf-8'
    ) -> AsyncIterator[tuple[int, str]]:
        """
        Read file lines asynchronously with line numbers.
        
        Args:
            file_path: Path to file
            encoding: File encoding
            
        Yields:
            Tuples of (line_number, line_content)
        """
        import aiofiles
        
        async with aiofiles.open(file_path, 'r', encoding=encoding) as f:
            line_num = 0
            async for line in f:
                line_num += 1
                yield line_num, line.rstrip('\n\r')
    
    async def _parse_log_line(
        self, 
        line: str, 
        line_num: int, 
        context: Dict[str, Any]
    ) -> Optional[NetworkTrace]:
        """
        Parse a single log line and potentially create a NetworkTrace.
        
        Args:
            line: Log line content
            line_num: Line number
            context: Parsing context for correlation
            
        Returns:
            NetworkTrace if this line represents a complete request/response, None otherwise
        """
        # Extract timestamp
        timestamp_match = self.patterns['timestamp'].search(line)
        timestamp_str = timestamp_match.group(1) if timestamp_match else None
        timestamp = self._parse_timestamp(timestamp_str) if timestamp_str else None
        
        # Update context with connection info
        self._update_context_from_line(line, line_num, timestamp, context)
        
        # Check if this line represents a request
        request_match = self.patterns['request'].search(line)
        if request_match:
            method, url = request_match.groups()
            
            # Store request in context for response correlation
            request_data = {
                'method': method,
                'url': url,
                'timestamp': timestamp,
                'line_number': line_num,
                'domain': self._extract_domain(url),
                'client_id': context.get('current_client'),
                'server': context.get('current_server'),
                'server_ip': context.get('current_server_ip'),
            }
            
            context['pending_request'] = request_data
            return None  # Wait for response to create complete trace
        
        # Check if this line represents a response
        response_match = self.patterns['response'].search(line)
        if response_match and 'pending_request' in context:
            status_code = int(response_match.group(1))
            status_text = response_match.group(2)
            
            # Get the pending request
            request_data = context.pop('pending_request')
            
            # Create HTTP request object
            request = HttpRequest(
                method=request_data['method'],
                url=request_data['url'],
                headers=[],  # Mitmproxy logs don't typically include full headers
                body=None,
                timestamp=request_data['timestamp'],
            )
            
            # Create HTTP response object
            response = HttpResponse(
                status_code=status_code,
                status_text=status_text,
                headers=[],
                body=None,
                size=0,
            )
            
            # Create timing info (limited from mitmproxy logs)
            timing = TimingInfo(
                dns_lookup=-1,
                tcp_connect=-1,
                ssl_handshake=-1,
                request_sent=-1,
                waiting=-1,
                content_download=-1,
                blocked=-1,
            )
            
            # Create network trace
            trace_id = f"mitm_{line_num}"
            domain = request_data['domain']
            
            trace = NetworkTrace(
                trace_id=trace_id,
                metadata={
                    'source_format': LogFormat.MITMPROXY.value,
                    'request_line': request_data['line_number'],
                    'response_line': line_num,
                    'domain': domain,
                    'client_id': request_data.get('client_id'),
                    'server': request_data.get('server'),
                    'server_ip': request_data.get('server_ip'),
                    'is_service': self._is_service_domain(domain),
                    'is_ip_detection': self._is_ip_detection_service(domain),
                    'is_oauth': self._is_oauth_related(request_data['url']),
                    'is_secure': request_data['url'].startswith('https://'),
                    'has_proxy_headers': self.service_patterns['proxy_headers'].search(line) is not None,
                    # Store HTTP data in metadata
                    'http_request': request.model_dump(),
                    'http_response': response.model_dump(),
                    'http_timing': timing.model_dump(),
                    'timestamp': (timestamp or request_data['timestamp']).isoformat() if (timestamp or request_data['timestamp']) else None,
                }
            )
            
            return trace
        
        return None
    
    def _update_context_from_line(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[datetime], 
        context: Dict[str, Any]
    ) -> None:
        """Update parsing context based on log line content."""
        
        # Client connections
        client_match = self.patterns['client_connect'].search(line)
        if client_match:
            context['current_client'] = client_match.group(1)
            return
        
        # Server connections
        server_match = self.patterns['server_connect'].search(line)
        if server_match:
            client_id, server, ip = server_match.groups()
            context['current_client'] = client_id
            context['current_server'] = server
            context['current_server_ip'] = ip
            return
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse mitmproxy timestamp string."""
        if not timestamp_str:
            return None
        
        try:
            # Mitmproxy timestamps are in HH:MM:SS.mmm format
            # We'll use today's date as base
            from datetime import date, time
            today = date.today()
            time_parts = timestamp_str.split(':')
            if len(time_parts) == 3:
                hour = int(time_parts[0])
                minute = int(time_parts[1])
                second_parts = time_parts[2].split('.')
                second = int(second_parts[0])
                microsecond = int(second_parts[1]) * 1000 if len(second_parts) > 1 else 0
                
                time_obj = time(hour, minute, second, microsecond)
                return datetime.combine(today, time_obj)
        except Exception:
            pass
        
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
            'client_errors': 0,
            'server_errors': 0,
            'tls_events': 0,
            'proxy_errors': 0,
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
        
        # Service-specific success rate
        service_traces = [t for t in traces if t.metadata and t.metadata.get('is_service')]
        if service_traces:
            successful_service = len([
                t for t in service_traces 
                if t.metadata and t.metadata.get('http_response', {}).get('status_code', 0) >= 200 
                and t.metadata.get('http_response', {}).get('status_code', 0) < 300
            ])
            stats['service_success_rate'] = (successful_service / len(service_traces)) * 100
        else:
            stats['service_success_rate'] = 0
