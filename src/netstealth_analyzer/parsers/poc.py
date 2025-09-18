"""
Async POC execution log parser for NetStealth Analyzer.

This module parses logs from network stealth POC execution to extract
exit IP detection, OAuth flow results, and session execution details with full async support.
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Union

from .base import BaseLogParser, ParseResult
from ..models.enums import LogFormat
from ..models.network import NetworkTrace, HttpRequest, HttpResponse, TimingInfo
from ..core.events import EventBus


class PocExecutionParser(BaseLogParser):
    """Async parser for POC execution logs from proxy POC scripts."""
    
    def __init__(
        self, 
        event_bus: Optional[EventBus] = None,
        service_domains: Optional[List[str]] = None,
        target_geography: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize POC execution parser.
        
        Args:
            event_bus: Optional event bus for progress notifications
            service_domains: List of service domains to analyze
            target_geography: Target geography configuration for IP validation
        """
        super().__init__(event_bus, service_domains)
        self.target_geography = target_geography or {}
        
        # Patterns for POC log entries
        self.patterns = {
            'timestamp': re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'),
            'log_level': re.compile(r'(DEBUG|INFO|WARNING|ERROR|CRITICAL)'),
            'exit_ip_detected': re.compile(r'EXIT_IP_DETECTED:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'),
            'httpbin_response': re.compile(r'mitmproxy test response:\s*(.+)'),
            'oauth_step': re.compile(r'OAuth.*?(success|failed|complete|redirect)', re.IGNORECASE),
            'service_login': re.compile(r'(login|auth).*?service', re.IGNORECASE),
            'proxy_connection': re.compile(r'proxy.*?connect|upstream.*?connect', re.IGNORECASE),
            'browser_startup': re.compile(r'browser.*?start|chrome.*?start', re.IGNORECASE),
            'error_pattern': re.compile(r'error|exception|failed|timeout', re.IGNORECASE),
            'success_pattern': re.compile(r'success|complete|ok|200', re.IGNORECASE),
        }
        
        # Service-specific patterns
        self.service_patterns = {
            'oauth_redirect': re.compile(r'redirect.*?service|service.*?redirect', re.IGNORECASE),
            'datadome_bypass': re.compile(r'datadome.*?bypass|bypass.*?datadome', re.IGNORECASE),
            'geo_detection': re.compile(r'geo.*?detect|location.*?detect', re.IGNORECASE),
        }
        
        # Build geography patterns
        self._build_geography_patterns()
    
    def _build_geography_patterns(self) -> None:
        """Build geography detection patterns from configuration."""
        self.target_ip_patterns = []
        
        # Build IP range patterns if specified
        ip_ranges = self.target_geography.get('ip_ranges', [])
        for ip_range in ip_ranges:
            if '/' in ip_range:
                base_ip = ip_range.split('/')[0]
                # For simplicity, match the first 3 octets for /24 networks
                if ip_range.endswith('/24'):
                    base_parts = base_ip.split('.')[:3]
                    pattern = r'\.'.join(base_parts) + r'\.\d{1,3}'
                    self.target_ip_patterns.append(re.compile(pattern))
            else:
                # Exact IP match
                escaped_ip = re.escape(ip_range)
                self.target_ip_patterns.append(re.compile(escaped_ip))
        
        # Build country/region patterns
        country_code = self.target_geography.get('country_code', '')
        country_name = self.target_geography.get('country_name', '')
        
        if country_code or country_name:
            country_indicators = [country_code.lower(), country_name.lower()]
            geo_pattern = '|'.join(re.escape(indicator) for indicator in country_indicators if indicator)
            self.target_geo_pattern = re.compile(f'({geo_pattern})', re.IGNORECASE)
        else:
            self.target_geo_pattern = None
    
    @property
    def supported_format(self) -> LogFormat:
        """Get the log format this parser supports."""
        return LogFormat.POC_EXECUTION
    
    @property
    def file_extensions(self) -> List[str]:
        """Get supported file extensions."""
        return ['.log', '.txt', '.poc']
    
    async def parse(
        self, 
        file_path: Union[str, Path],
        **kwargs
    ) -> ParseResult:
        """
        Parse POC execution log file asynchronously.
        
        Args:
            file_path: Path to POC execution log file
            **kwargs: Additional options (unused for POC logs)
            
        Returns:
            ParseResult containing parsed events and session information
            
        Raises:
            ValueError: If log file format is invalid
            FileNotFoundError: If file doesn't exist
            PermissionError: If file can't be read
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"POC execution log file not found: {path}")
        
        self._emit_progress("poc_parse_started", {"file": str(path)})
        
        try:
            # Parse log file line by line
            network_traces = []
            statistics = self._init_statistics()
            errors = []
            events = []
            line_count = 0
            session_start = None
            session_end = None
            
            async for line_num, line in self._read_file_lines_with_numbers(path):
                line_count += 1
                
                if not line.strip():
                    continue
                
                try:
                    # Parse line for events
                    line_events, timestamp = await self._parse_poc_line(line, line_num)
                    events.extend(line_events)
                    
                    # Track session timing
                    if timestamp:
                        if session_start is None:
                            session_start = timestamp
                        session_end = timestamp
                    
                    # Update statistics
                    for event in line_events:
                        self._update_statistics_from_event(statistics, event)
                    
                    # Emit progress for every 1000 lines
                    if line_count % 1000 == 0:
                        self._emit_progress("poc_lines_processed", {
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
            
            # Create session info
            session_info = self._create_session_info(session_start, session_end, events)
            
            # Create metadata
            metadata = {
                'line_count': line_count,
                'parser_version': '2.0',
                'events_parsed': len(events),
                'session_info': session_info,
            }
            
            # Finalize statistics
            self._finalize_statistics(statistics, events)
            
            result = ParseResult(
                format=LogFormat.POC_EXECUTION,
                source_file=str(path),
                metadata=metadata,
                network_traces=network_traces,  # POC logs typically don't create network traces
                statistics=statistics,
                errors=errors
            )
            
            self._emit_progress("poc_parse_completed", {
                "events": len(events),
                "errors": len(errors),
                "lines": line_count
            })
            
            return result
            
        except Exception as e:
            self._emit_progress("poc_parse_failed", {"error": str(e)})
            raise
    
    async def stream_parse(
        self, 
        file_path: Union[str, Path],
        **kwargs
    ) -> AsyncIterator[NetworkTrace]:
        """
        Parse POC execution log file and yield traces as they're processed.
        
        Note: POC logs typically don't generate NetworkTrace objects,
        but this method is provided for interface compliance.
        
        Args:
            file_path: Path to POC execution log file
            **kwargs: Additional options (unused for POC logs)
            
        Yields:
            NetworkTrace objects (typically none for POC logs)
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"POC execution log file not found: {path}")
        
        self._emit_progress("poc_stream_started", {"file": str(path)})
        
        try:
            line_count = 0
            
            async for line_num, line in self._read_file_lines_with_numbers(path):
                line_count += 1
                
                if not line.strip():
                    continue
                
                try:
                    # POC logs typically don't generate network traces
                    # This is mainly for interface compliance
                    
                    # Emit progress for every 500 lines
                    if line_count % 500 == 0:
                        self._emit_progress("poc_stream_progress", {
                            "processed": line_count
                        })
                        
                except Exception as e:
                    # Log error but continue processing
                    self._emit_progress("poc_line_error", {
                        "line_number": line_num,
                        "error": str(e)
                    })
                    continue
            
            self._emit_progress("poc_stream_completed", {"lines": line_count})
            
        except Exception as e:
            self._emit_progress("poc_stream_failed", {"error": str(e)})
            raise
        
        # POC logs don't typically yield network traces
        return
        yield  # Make this a generator
    
    async def _validate_format(self, file_path: Path) -> bool:
        """
        Validate POC execution log file format.
        
        Args:
            file_path: Path to log file
            
        Returns:
            True if file appears to be a POC execution log
        """
        try:
            # Read first few lines to check for POC log patterns
            line_count = 0
            poc_indicators = 0
            
            async for line in self._read_file_lines_async(file_path):
                line_count += 1
                
                # Check for POC-specific patterns
                if (any(pattern.search(line) for pattern in self.patterns.values()) or
                    'poc' in line.lower() or
                    'exit_ip' in line.lower() or
                    'oauth' in line.lower() or
                    'proxy' in line.lower()):
                    poc_indicators += 1
                
                # Check first 50 lines
                if line_count >= 50:
                    break
            
            # Consider valid if we found POC patterns in at least 15% of lines
            return line_count > 0 and (poc_indicators / line_count) >= 0.15
            
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
    
    async def _parse_poc_line(
        self, 
        line: str, 
        line_num: int
    ) -> tuple[List[Dict[str, Any]], Optional[datetime]]:
        """
        Parse a single POC log line and extract events.
        
        Args:
            line: Log line content
            line_num: Line number
            
        Returns:
            Tuple of (events list, timestamp)
        """
        events = []
        
        # Extract basic information
        timestamp = self._extract_timestamp(line)
        log_level = self._extract_log_level(line)
        
        # Parse different types of events
        events.extend(self._parse_exit_ips(line, line_num, timestamp, log_level))
        events.extend(self._parse_oauth_events(line, line_num, timestamp, log_level))
        events.extend(self._parse_browser_events(line, line_num, timestamp, log_level))
        events.extend(self._parse_proxy_events(line, line_num, timestamp, log_level))
        events.extend(self._parse_service_events(line, line_num, timestamp, log_level))
        events.extend(self._parse_error_events(line, line_num, timestamp, log_level))
        
        return events, timestamp
    
    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        """Extract timestamp from log line."""
        timestamp_match = self.patterns['timestamp'].search(line)
        if timestamp_match:
            timestamp_str = timestamp_match.group(1)
            try:
                return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                pass
        return None
    
    def _extract_log_level(self, line: str) -> str:
        """Extract log level from log line."""
        log_level_match = self.patterns['log_level'].search(line)
        return log_level_match.group(1) if log_level_match else 'INFO'
    
    def _parse_exit_ips(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[datetime],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse exit IP detection events."""
        events = []
        
        # Direct EXIT_IP_DETECTED entries
        exit_ip_match = self.patterns['exit_ip_detected'].search(line)
        if exit_ip_match:
            detected_ip = exit_ip_match.group(1)
            exit_ip_event = {
                'type': 'exit_ip_detection',
                'ip_address': detected_ip,
                'detection_method': 'poc_enhanced_logging',
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'is_target_geo_ip': self._is_target_geography_ip(detected_ip),
                'verification_source': 'EXIT_IP_DETECTED log entry'
            }
            events.append(exit_ip_event)
            return events
        
        # httpbin.org/ip response parsing
        httpbin_match = self.patterns['httpbin_response'].search(line)
        if httpbin_match:
            try:
                response_text = httpbin_match.group(1)
                # Try to parse as JSON
                json_start = response_text.find('{')
                json_end = response_text.rfind('}') + 1
                
                if json_start != -1 and json_end > json_start:
                    json_str = response_text[json_start:json_end]
                    response_data = json.loads(json_str)
                    origin_ip = response_data.get('origin', '').strip()
                    
                    if origin_ip and self._is_valid_ip(origin_ip):
                        exit_ip_event = {
                            'type': 'exit_ip_detection',
                            'ip_address': origin_ip,
                            'detection_method': 'httpbin_test_response',
                            'timestamp': timestamp.isoformat() if timestamp else None,
                            'line_number': line_num,
                            'log_level': log_level,
                            'is_target_geo_ip': self._is_target_geography_ip(origin_ip),
                            'verification_source': 'httpbin.org/ip response',
                            'raw_response': response_text[:200]  # First 200 chars
                        }
                        events.append(exit_ip_event)
                
            except json.JSONDecodeError:
                # Try regex extraction as fallback
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', response_text)
                if ip_match:
                    potential_ip = ip_match.group(1)
                    if self._is_valid_ip(potential_ip):
                        exit_ip_event = {
                            'type': 'exit_ip_detection',
                            'ip_address': potential_ip,
                            'detection_method': 'httpbin_regex_extraction',
                            'timestamp': timestamp.isoformat() if timestamp else None,
                            'line_number': line_num,
                            'log_level': log_level,
                            'is_target_geo_ip': self._is_target_geography_ip(potential_ip),
                            'verification_source': 'httpbin response (regex)',
                            'raw_response': response_text[:200]
                        }
                        events.append(exit_ip_event)
        
        return events
    
    def _parse_oauth_events(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[datetime],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse OAuth-related events."""
        events = []
        
        if self.patterns['oauth_step'].search(line) or self.patterns['service_login'].search(line):
            oauth_event = {
                'type': 'oauth_event',
                'event_description': line.strip(),
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'is_success': bool(self.patterns['success_pattern'].search(line)),
                'is_error': bool(self.patterns['error_pattern'].search(line)),
                'is_redirect': bool(self.service_patterns['oauth_redirect'].search(line)),
                'step_type': self._classify_oauth_step(line)
            }
            events.append(oauth_event)
        
        return events
    
    def _parse_browser_events(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[datetime],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse browser-related events."""
        events = []
        
        if self.patterns['browser_startup'].search(line):
            browser_event = {
                'type': 'browser_event',
                'event_type': 'browser_startup',
                'event_description': line.strip(),
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'is_success': bool(self.patterns['success_pattern'].search(line)),
                'is_error': bool(self.patterns['error_pattern'].search(line)),
            }
            events.append(browser_event)
        
        return events
    
    def _parse_proxy_events(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[datetime],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse proxy-related events."""
        events = []
        
        if self.patterns['proxy_connection'].search(line):
            proxy_event = {
                'type': 'proxy_event',
                'event_type': 'proxy_connection',
                'event_description': line.strip(),
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'is_success': bool(self.patterns['success_pattern'].search(line)),
                'is_error': bool(self.patterns['error_pattern'].search(line)),
                'is_upstream': 'upstream' in line.lower(),
            }
            events.append(proxy_event)
        
        return events
    
    def _parse_service_events(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[datetime],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse service-specific events."""
        events = []
        
        if any(domain in line for domain in self.service_domains):
            service_event = {
                'type': 'service_event',
                'event_description': line.strip(),
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'url_accessed': self._extract_service_url(line),
                'is_oauth_related': bool(self.service_patterns['oauth_redirect'].search(line)),
                'is_datadome_related': bool(self.service_patterns['datadome_bypass'].search(line)),
                'is_success': bool(self.patterns['success_pattern'].search(line)),
            }
            events.append(service_event)
        
        return events
    
    def _parse_error_events(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[datetime],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse error events."""
        events = []
        
        if (self.patterns['error_pattern'].search(line) or 
            log_level in ['ERROR', 'CRITICAL']):
            
            error_event = {
                'type': 'error_event',
                'error_description': line.strip(),
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'error_type': self._classify_error_type(line),
                'is_critical': log_level == 'CRITICAL',
                'is_service_related': any(domain in line for domain in self.service_domains),
            }
            events.append(error_event)
        
        return events
    
    def _classify_oauth_step(self, line: str) -> str:
        """Classify OAuth step type."""
        line_lower = line.lower()
        if 'redirect' in line_lower:
            return 'redirect'
        elif 'authorize' in line_lower:
            return 'authorization'
        elif 'token' in line_lower:
            return 'token_exchange'
        elif 'login' in line_lower:
            return 'login_page'
        else:
            return 'unknown'
    
    def _classify_error_type(self, line: str) -> str:
        """Classify error type."""
        line_lower = line.lower()
        if 'timeout' in line_lower:
            return 'timeout'
        elif 'connection' in line_lower:
            return 'connection_error'
        elif 'tls' in line_lower or 'ssl' in line_lower:
            return 'tls_error'
        elif 'proxy' in line_lower:
            return 'proxy_error'
        elif 'browser' in line_lower or 'chrome' in line_lower:
            return 'browser_error'
        elif 'auth' in line_lower or 'oauth' in line_lower:
            return 'authentication_error'
        else:
            return 'general_error'
    
    def _extract_service_url(self, line: str) -> Optional[str]:
        """Extract service URL from log line."""
        # Try to extract full URL
        url_start = line.find('http')
        if url_start != -1:
            # Find end of URL (space or end of line)
            url_end = line.find(' ', url_start)
            if url_end == -1:
                url_end = len(line)
            return line[url_start:url_end].strip()
        
        # Look for domain names
        for domain in self.service_domains:
            if domain in line:
                return domain
        
        return None
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if not 0 <= num <= 255:
                    return False
            return True
        except (ValueError, AttributeError):
            return False
    
    def _is_target_geography_ip(self, ip_address: str) -> bool:
        """
        Check if IP address matches target geography configuration.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP matches target geography patterns
        """
        # Check against configured IP ranges
        for pattern in self.target_ip_patterns:
            if pattern.search(ip_address):
                return True
        
        # If no IP ranges configured, assume any IP could be valid
        # (geographic detection would need external IP geolocation service)
        if not self.target_ip_patterns:
            return True
        
        return False
    
    def _create_session_info(
        self, 
        session_start: Optional[datetime], 
        session_end: Optional[datetime], 
        events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create session information from parsed events."""
        session_info = {
            'start_time': session_start.isoformat() if session_start else None,
            'end_time': session_end.isoformat() if session_end else None,
            'duration_seconds': 0,
            'success': False,
        }
        
        if session_start and session_end:
            duration = (session_end - session_start).total_seconds()
            session_info['duration_seconds'] = duration
            
            # Determine session success
            exit_ip_events = [e for e in events if e.get('type') == 'exit_ip_detection']
            oauth_events = [e for e in events if e.get('type') == 'oauth_event']
            error_events = [e for e in events if e.get('type') == 'error_event']
            
            success_indicators = [
                len(exit_ip_events) > 0,
                len(oauth_events) > 0,
                len(error_events) < 5,
                any(e.get('is_success') for e in oauth_events)
            ]
            session_info['success'] = sum(success_indicators) >= 2
        
        return session_info
    
    def _init_statistics(self) -> Dict[str, Any]:
        """Initialize statistics dictionary."""
        return {
            'exit_ips_detected': 0,
            'oauth_steps_completed': 0,
            'errors_count': 0,
            'service_requests': 0,
            'target_geo_ips_found': 0,
            'browser_events': 0,
            'proxy_events': 0,
            'critical_errors': 0,
        }
    
    def _update_statistics_from_event(self, stats: Dict[str, Any], event: Dict[str, Any]) -> None:
        """Update statistics with event data."""
        event_type = event.get('type', '')
        
        if event_type == 'exit_ip_detection':
            stats['exit_ips_detected'] += 1
            if event.get('is_target_geo_ip'):
                stats['target_geo_ips_found'] += 1
        elif event_type == 'oauth_event':
            if event.get('is_success'):
                stats['oauth_steps_completed'] += 1
        elif event_type == 'error_event':
            stats['errors_count'] += 1
            if event.get('is_critical'):
                stats['critical_errors'] += 1
        elif event_type == 'service_event':
            stats['service_requests'] += 1
        elif event_type == 'browser_event':
            stats['browser_events'] += 1
        elif event_type == 'proxy_event':
            stats['proxy_events'] += 1
    
    def _finalize_statistics(self, stats: Dict[str, Any], events: List[Dict[str, Any]]) -> None:
        """Finalize statistics calculations."""
        # Calculate success rate
        total_events = (stats['oauth_steps_completed'] + stats['browser_events'] + 
                       stats['proxy_events'] + stats['service_requests'])
        
        if total_events > 0:
            oauth_events = [e for e in events if e.get('type') == 'oauth_event']
            browser_events = [e for e in events if e.get('type') == 'browser_event']
            proxy_events = [e for e in events if e.get('type') == 'proxy_event']
            service_events = [e for e in events if e.get('type') == 'service_event']
            
            successful_events = sum([
                len([e for e in oauth_events if e.get('is_success')]),
                len([e for e in browser_events if e.get('is_success')]),
                len([e for e in proxy_events if e.get('is_success')]),
                len([e for e in service_events if e.get('is_success')])
            ])
            stats['success_rate'] = (successful_events / total_events) * 100
        else:
            stats['success_rate'] = 0
        
        # Count unique detected IPs
        exit_ip_events = [e for e in events if e.get('type') == 'exit_ip_detection']
        unique_ips = set(e.get('ip_address') for e in exit_ip_events if e.get('ip_address'))
        stats['unique_exit_ips'] = len(unique_ips)
        
        # Count target geography IP percentage
        if stats['exit_ips_detected'] > 0:
            stats['target_geo_ip_percentage'] = (stats['target_geo_ips_found'] / stats['exit_ips_detected']) * 100
        else:
            stats['target_geo_ip_percentage'] = 0
        
        # OAuth completion rate
        oauth_events = [e for e in events if e.get('type') == 'oauth_event']
        oauth_attempts = len(oauth_events)
        if oauth_attempts > 0:
            stats['oauth_completion_rate'] = (stats['oauth_steps_completed'] / oauth_attempts) * 100
        else:
            stats['oauth_completion_rate'] = 0
        
        # Session health score
        health_factors = [
            stats['success_rate'] / 100,
            1.0 if stats['exit_ips_detected'] > 0 else 0.0,
            1.0 if stats['target_geo_ips_found'] > 0 else 0.0,
            max(0.0, 1.0 - (stats['critical_errors'] / 10.0)),  # Penalty for critical errors
            stats['oauth_completion_rate'] / 100
        ]
        stats['session_health_score'] = (sum(health_factors) / len(health_factors)) * 100
