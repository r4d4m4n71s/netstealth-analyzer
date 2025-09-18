"""
Async Browser log parser for NetStealth Analyzer.

This module parses browser console logs and debug output to detect
automation signatures, JavaScript errors, and stealth-related issues with full async support.
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


class BrowserLogParser(BaseLogParser):
    """Async parser for browser console and Chrome debug logs."""
    
    def __init__(
        self, 
        event_bus: Optional[EventBus] = None,
        service_domains: Optional[List[str]] = None
    ):
        """
        Initialize browser log parser.
        
        Args:
            event_bus: Optional event bus for progress notifications
            service_domains: List of service domains to analyze
        """
        super().__init__(event_bus, service_domains)
        
        # Common browser log patterns
        self.patterns = {
            'timestamp': re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'),
            'log_level': re.compile(r'(VERBOSE|DEBUG|INFO|WARN|WARNING|ERROR|SEVERE|FATAL)', re.IGNORECASE),
            'chrome_level': re.compile(r'\[(INFO|WARNING|ERROR|FATAL)\]'),
            'console_log': re.compile(r'console\.(log|info|warn|error|debug)', re.IGNORECASE),
            'javascript_error': re.compile(r'(uncaught|unhandled).*?(error|exception)', re.IGNORECASE),
            'network_error': re.compile(r'net::|network.*?error|failed to load', re.IGNORECASE),
            'security_error': re.compile(r'security.*?error|cors.*?error|csp.*?violation', re.IGNORECASE),
        }
        
        # Detection and fingerprinting patterns
        self.detection_patterns = {
            'webdriver_detection': re.compile(r'webdriver|selenium|chromedriver|automation', re.IGNORECASE),
            'bot_detection': re.compile(r'bot.*?detect|automated.*?browser|headless.*?detect', re.IGNORECASE),
            'fingerprinting': re.compile(r'canvas.*?fingerprint|audio.*?fingerprint|webgl.*?fingerprint', re.IGNORECASE),
            'datadome_detection': re.compile(r'datadome|captcha.*?delivery|challenge.*?detect', re.IGNORECASE),
            'tls_fingerprint': re.compile(r'tls.*?fingerprint|ja3|ssl.*?fingerprint', re.IGNORECASE),
            'user_agent_check': re.compile(r'user.*?agent.*?check|navigator.*?check', re.IGNORECASE),
            'viewport_check': re.compile(r'viewport|screen.*?resolution|window.*?size', re.IGNORECASE),
        }
        
        # Service-specific patterns
        self.service_patterns = {
            'service_api': re.compile(r'service.*?api|api.*?service', re.IGNORECASE),
            'oauth_flow': re.compile(r'oauth|authorize|token.*?exchange', re.IGNORECASE),
            'player_errors': re.compile(r'player.*?error|playback.*?error|audio.*?error', re.IGNORECASE),
        }
    
    @property
    def supported_format(self) -> LogFormat:
        """Get the log format this parser supports."""
        return LogFormat.BROWSER_CONSOLE
    
    @property
    def file_extensions(self) -> List[str]:
        """Get supported file extensions."""
        return ['.log', '.txt', '.console']
    
    async def parse(
        self, 
        file_path: Union[str, Path],
        **kwargs
    ) -> ParseResult:
        """
        Parse browser log file asynchronously.
        
        Args:
            file_path: Path to browser log file
            **kwargs: Additional options (unused for browser logs)
            
        Returns:
            ParseResult containing parsed network traces and events
            
        Raises:
            ValueError: If log file format is invalid
            FileNotFoundError: If file doesn't exist
            PermissionError: If file can't be read
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Browser log file not found: {path}")
        
        self._emit_progress("browser_parse_started", {"file": str(path)})
        
        try:
            # Parse log file line by line
            network_traces = []
            statistics = self._init_statistics()
            errors = []
            events = []
            line_count = 0
            
            async for line_num, line in self._read_file_lines_with_numbers(path):
                line_count += 1
                
                if not line.strip():
                    continue
                
                try:
                    # Parse line for events and potential network traces
                    line_events = await self._parse_browser_line(line, line_num)
                    events.extend(line_events)
                    
                    # Update statistics
                    for event in line_events:
                        self._update_statistics_from_event(statistics, event)
                    
                    # Emit progress for every 1000 lines
                    if line_count % 1000 == 0:
                        self._emit_progress("browser_lines_processed", {
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
                'log_format': self._detect_browser_log_format(path).value,
                'events_parsed': len(events),
            }
            
            # Finalize statistics
            self._finalize_statistics(statistics, events)
            
            result = ParseResult(
                format=LogFormat.BROWSER_CONSOLE,
                source_file=str(path),
                metadata=metadata,
                network_traces=network_traces,  # Browser logs typically don't create network traces
                statistics=statistics,
                errors=errors
            )
            
            self._emit_progress("browser_parse_completed", {
                "events": len(events),
                "errors": len(errors),
                "lines": line_count
            })
            
            return result
            
        except Exception as e:
            self._emit_progress("browser_parse_failed", {"error": str(e)})
            raise
    
    async def stream_parse(
        self, 
        file_path: Union[str, Path],
        **kwargs
    ) -> AsyncIterator[NetworkTrace]:
        """
        Parse browser log file and yield traces as they're processed.
        
        Note: Browser logs typically don't generate NetworkTrace objects,
        but this method is provided for interface compliance.
        
        Args:
            file_path: Path to browser log file
            **kwargs: Additional options (unused for browser logs)
            
        Yields:
            NetworkTrace objects (typically none for browser logs)
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Browser log file not found: {path}")
        
        self._emit_progress("browser_stream_started", {"file": str(path)})
        
        try:
            line_count = 0
            
            async for line_num, line in self._read_file_lines_with_numbers(path):
                line_count += 1
                
                if not line.strip():
                    continue
                
                try:
                    # Browser logs typically don't generate network traces
                    # This is mainly for interface compliance
                    
                    # Emit progress for every 500 lines
                    if line_count % 500 == 0:
                        self._emit_progress("browser_stream_progress", {
                            "processed": line_count
                        })
                        
                except Exception as e:
                    # Log error but continue processing
                    self._emit_progress("browser_line_error", {
                        "line_number": line_num,
                        "error": str(e)
                    })
                    continue
            
            self._emit_progress("browser_stream_completed", {"lines": line_count})
            
        except Exception as e:
            self._emit_progress("browser_stream_failed", {"error": str(e)})
            raise
        
        # Browser logs don't typically yield network traces
        return
        yield  # Make this a generator
    
    async def _validate_format(self, file_path: Path) -> bool:
        """
        Validate browser log file format.
        
        Args:
            file_path: Path to log file
            
        Returns:
            True if file appears to be a browser log
        """
        try:
            # Read first few lines to check for browser log patterns
            line_count = 0
            browser_indicators = 0
            
            async for line in self._read_file_lines_async(file_path):
                line_count += 1
                
                # Check for browser-specific patterns
                if (any(pattern.search(line) for pattern in self.patterns.values()) or
                    any(pattern.search(line) for pattern in self.detection_patterns.values()) or
                    'console' in line.lower() or
                    'chrome' in line.lower() or
                    'browser' in line.lower()):
                    browser_indicators += 1
                
                # Check first 50 lines
                if line_count >= 50:
                    break
            
            # Consider valid if we found browser patterns in at least 20% of lines
            return line_count > 0 and (browser_indicators / line_count) >= 0.2
            
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
    
    async def _parse_browser_line(
        self, 
        line: str, 
        line_num: int
    ) -> List[Dict[str, Any]]:
        """
        Parse a single browser log line and extract events.
        
        Args:
            line: Log line content
            line_num: Line number
            
        Returns:
            List of events extracted from the line
        """
        events = []
        
        # Extract basic information
        timestamp = self._extract_timestamp(line)
        log_level = self._extract_log_level(line)
        
        # Parse different types of events
        events.extend(self._parse_console_logs(line, line_num, timestamp, log_level))
        events.extend(self._parse_javascript_errors(line, line_num, timestamp, log_level))
        events.extend(self._parse_network_errors(line, line_num, timestamp, log_level))
        events.extend(self._parse_security_issues(line, line_num, timestamp, log_level))
        events.extend(self._parse_detection_events(line, line_num, timestamp, log_level))
        events.extend(self._parse_service_events(line, line_num, timestamp, log_level))
        events.extend(self._parse_browser_events(line, line_num, timestamp, log_level))
        
        return events
    
    def _detect_browser_log_format(self, log_path: Path) -> LogFormat:
        """Detect browser log format from filename."""
        name = log_path.name.lower()
        if 'chrome_debug' in name or 'chrome.log' in name:
            return LogFormat.CHROME_DEBUG
        else:
            return LogFormat.BROWSER_CONSOLE
    
    def _extract_timestamp(self, line: str) -> Optional[str]:
        """Extract timestamp from log line."""
        timestamp_match = self.patterns['timestamp'].search(line)
        return timestamp_match.group(1) if timestamp_match else None
    
    def _extract_log_level(self, line: str) -> str:
        """Extract log level from log line."""
        # Try Chrome-style log level
        chrome_match = self.patterns['chrome_level'].search(line)
        if chrome_match:
            return chrome_match.group(1).upper()
        
        # Try general log level pattern
        level_match = self.patterns['log_level'].search(line)
        if level_match:
            level = level_match.group(1).upper()
            # Normalize some common variations
            if level in ['WARN', 'WARNING']:
                return 'WARNING'
            elif level in ['SEVERE', 'FATAL']:
                return 'ERROR'
            return level
        
        # Determine level from content
        line_lower = line.lower()
        if 'error' in line_lower or 'exception' in line_lower:
            return 'ERROR'
        elif 'warning' in line_lower or 'warn' in line_lower:
            return 'WARNING'
        else:
            return 'INFO'
    
    def _parse_console_logs(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[str],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse console.log statements."""
        events = []
        
        if self.patterns['console_log'].search(line):
            console_entry = {
                'type': 'console_log',
                'message': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'console_method': self._extract_console_method(line),
                'is_service_related': any(domain in line for domain in self.service_domains),
                'is_detection_related': any(pattern.search(line) for pattern in self.detection_patterns.values())
            }
            events.append(console_entry)
        
        return events
    
    def _parse_javascript_errors(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[str],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse JavaScript errors."""
        events = []
        
        if (self.patterns['javascript_error'].search(line) or 
            log_level == 'ERROR' and ('script' in line.lower() or 'js' in line.lower())):
            
            js_error = {
                'type': 'javascript_error',
                'error_message': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'error_type': self._classify_js_error(line),
                'source_url': self._extract_source_url(line),
                'is_service_related': any(domain in line for domain in self.service_domains),
                'is_critical': 'uncaught' in line.lower() or 'unhandled' in line.lower(),
            }
            events.append(js_error)
        
        return events
    
    def _parse_network_errors(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[str],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse network-related errors."""
        events = []
        
        if self.patterns['network_error'].search(line):
            network_error = {
                'type': 'network_error',
                'error_message': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'error_code': self._extract_error_code(line),
                'url': self._extract_source_url(line),
                'is_service_related': any(domain in line for domain in self.service_domains),
                'is_timeout': 'timeout' in line.lower(),
                'is_connection_error': 'connection' in line.lower() or 'refused' in line.lower(),
            }
            events.append(network_error)
        
        return events
    
    def _parse_security_issues(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[str],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse security-related issues."""
        events = []
        
        if self.patterns['security_error'].search(line):
            security_issue = {
                'type': 'security_issue',
                'issue_description': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'issue_type': self._classify_security_issue(line),
                'source_url': self._extract_source_url(line),
                'is_service_related': any(domain in line for domain in self.service_domains),
                'severity': self._assess_security_severity(line),
            }
            events.append(security_issue)
        
        return events
    
    def _parse_detection_events(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[str],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse automation/bot detection events."""
        events = []
        detected_patterns = []
        
        for pattern_name, pattern in self.detection_patterns.items():
            if pattern.search(line):
                detected_patterns.append(pattern_name)
        
        if detected_patterns:
            detection_event = {
                'type': 'detection_event',
                'event_description': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'detection_types': detected_patterns,
                'is_webdriver_detected': 'webdriver_detection' in detected_patterns,
                'is_bot_detected': 'bot_detection' in detected_patterns,
                'is_fingerprinting': 'fingerprinting' in detected_patterns,
                'is_datadome_related': 'datadome_detection' in detected_patterns,
                'risk_level': self._assess_detection_risk(detected_patterns),
            }
            events.append(detection_event)
        
        return events
    
    def _parse_service_events(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[str],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse service-specific events."""
        events = []
        
        if (any(domain in line for domain in self.service_domains) or
            any(pattern.search(line) for pattern in self.service_patterns.values())):
            
            service_event = {
                'type': 'service_event',
                'event_description': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'event_category': self._classify_service_event(line),
                'is_api_related': bool(self.service_patterns['service_api'].search(line)),
                'is_oauth_related': bool(self.service_patterns['oauth_flow'].search(line)),
                'is_player_error': bool(self.service_patterns['player_errors'].search(line)),
                'severity': log_level,
            }
            events.append(service_event)
        
        return events
    
    def _parse_browser_events(
        self, 
        line: str, 
        line_num: int, 
        timestamp: Optional[str],
        log_level: str
    ) -> List[Dict[str, Any]]:
        """Parse general browser events."""
        events = []
        browser_keywords = ['navigate', 'load', 'unload', 'resize', 'focus', 'blur']
        
        if any(keyword in line.lower() for keyword in browser_keywords):
            browser_event = {
                'type': 'browser_event',
                'event_description': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'event_type': self._classify_browser_event(line),
                'is_navigation': 'navigate' in line.lower() or 'load' in line.lower(),
                'is_user_interaction': any(word in line.lower() for word in ['click', 'focus', 'blur']),
            }
            events.append(browser_event)
        
        return events
    
    def _extract_console_method(self, line: str) -> str:
        """Extract console method from line."""
        console_match = self.patterns['console_log'].search(line)
        if console_match:
            return console_match.group(1)
        return 'log'
    
    def _extract_source_url(self, line: str) -> Optional[str]:
        """Extract source URL from log line."""
        # Try to find URLs in the line
        url_pattern = re.compile(r'https?://[^\s]+')
        url_match = url_pattern.search(line)
        return url_match.group(0) if url_match else None
    
    def _extract_error_code(self, line: str) -> Optional[str]:
        """Extract error code from network error."""
        # Look for common network error patterns
        error_codes = ['ERR_NETWORK_CHANGED', 'ERR_CONNECTION_REFUSED', 'ERR_TIMEOUT', 
                      'ERR_NAME_NOT_RESOLVED', 'ERR_CERT_AUTHORITY_INVALID']
        
        for code in error_codes:
            if code in line:
                return code
        
        # Look for HTTP status codes
        status_match = re.search(r'\b(4\d{2}|5\d{2})\b', line)
        if status_match:
            return f"HTTP_{status_match.group(1)}"
        
        return None
    
    def _classify_js_error(self, line: str) -> str:
        """Classify JavaScript error type."""
        line_lower = line.lower()
        if 'syntax' in line_lower:
            return 'syntax_error'
        elif 'reference' in line_lower:
            return 'reference_error'
        elif 'type' in line_lower:
            return 'type_error'
        elif 'range' in line_lower:
            return 'range_error'
        elif 'uncaught' in line_lower:
            return 'uncaught_exception'
        else:
            return 'general_error'
    
    def _classify_security_issue(self, line: str) -> str:
        """Classify security issue type."""
        line_lower = line.lower()
        if 'cors' in line_lower:
            return 'cors_error'
        elif 'csp' in line_lower:
            return 'csp_violation'
        elif 'mixed content' in line_lower:
            return 'mixed_content'
        elif 'certificate' in line_lower or 'ssl' in line_lower:
            return 'certificate_error'
        else:
            return 'general_security'
    
    def _classify_service_event(self, line: str) -> str:
        """Classify service event type."""
        line_lower = line.lower()
        if self.service_patterns['service_api'].search(line):
            return 'api_event'
        elif self.service_patterns['oauth_flow'].search(line):
            return 'oauth_event'
        elif self.service_patterns['player_errors'].search(line):
            return 'player_event'
        elif 'login' in line_lower or 'auth' in line_lower:
            return 'authentication_event'
        else:
            return 'general_service'
    
    def _classify_browser_event(self, line: str) -> str:
        """Classify browser event type."""
        line_lower = line.lower()
        if 'navigate' in line_lower:
            return 'navigation'
        elif 'load' in line_lower:
            return 'page_load'
        elif 'resize' in line_lower:
            return 'window_resize'
        elif 'focus' in line_lower or 'blur' in line_lower:
            return 'focus_change'
        else:
            return 'general_browser'
    
    def _assess_security_severity(self, line: str) -> str:
        """Assess security issue severity."""
        line_lower = line.lower()
        if any(word in line_lower for word in ['critical', 'severe', 'blocked']):
            return 'high'
        elif any(word in line_lower for word in ['warning', 'deprecated']):
            return 'medium'
        else:
            return 'low'
    
    def _assess_detection_risk(self, detected_patterns: List[str]) -> str:
        """Assess detection risk level."""
        high_risk_patterns = ['webdriver_detection', 'bot_detection', 'datadome_detection']
        medium_risk_patterns = ['fingerprinting', 'tls_fingerprint']
        
        if any(pattern in high_risk_patterns for pattern in detected_patterns):
            return 'high'
        elif any(pattern in medium_risk_patterns for pattern in detected_patterns):
            return 'medium'
        else:
            return 'low'
    
    def _init_statistics(self) -> Dict[str, Any]:
        """Initialize statistics dictionary."""
        return {
            'total_log_entries': 0,
            'javascript_errors': 0,
            'detection_attempts': 0,
            'service_related_events': 0,
            'security_violations': 0,
            'console_logs': 0,
            'network_errors': 0,
            'browser_events': 0,
            'high_severity_events': 0,
            'unique_detection_types': set(),
        }
    
    def _update_statistics_from_event(self, stats: Dict[str, Any], event: Dict[str, Any]) -> None:
        """Update statistics with event data."""
        stats['total_log_entries'] += 1
        
        event_type = event.get('type', '')
        
        if event_type == 'javascript_error':
            stats['javascript_errors'] += 1
        elif event_type == 'detection_event':
            stats['detection_attempts'] += 1
            detection_types = event.get('detection_types', [])
            stats['unique_detection_types'].update(detection_types)
        elif event_type == 'service_event':
            stats['service_related_events'] += 1
        elif event_type == 'security_issue':
            stats['security_violations'] += 1
        elif event_type == 'console_log':
            stats['console_logs'] += 1
        elif event_type == 'network_error':
            stats['network_errors'] += 1
        elif event_type == 'browser_event':
            stats['browser_events'] += 1
        
        # Count high severity events
        if (event.get('is_critical') or 
            event.get('severity') == 'high' or 
            event.get('risk_level') == 'high' or
            event.get('log_level') in ['ERROR', 'SEVERE', 'FATAL']):
            stats['high_severity_events'] += 1
    
    def _finalize_statistics(self, stats: Dict[str, Any], events: List[Dict[str, Any]]) -> None:
        """Finalize statistics calculations."""
        # Convert sets to counts
        stats['unique_detection_types'] = len(stats['unique_detection_types'])
        
        # Calculate rates
        total = stats['total_log_entries']
        if total > 0:
            stats['error_rate'] = (stats['javascript_errors'] / total) * 100
            stats['service_event_percentage'] = (stats['service_related_events'] / total) * 100
            stats['detection_attempt_rate'] = (stats['detection_attempts'] / total) * 100
        else:
            stats['error_rate'] = 0
            stats['service_event_percentage'] = 0
            stats['detection_attempt_rate'] = 0
        
        # Browser health score
        if total > 0:
            health_factors = [
                max(0.0, 1.0 - (stats['error_rate'] / 100.0)),  # Lower error rate is better
                max(0.0, 1.0 - (stats['detection_attempt_rate'] / 100.0)),  # Lower detection rate is better
                max(0.0, 1.0 - (stats['high_severity_events'] / total)),  # Fewer severe events is better
                1.0 if stats['service_related_events'] > 0 else 0.5,  # Having service events indicates activity
            ]
            stats['browser_health_score'] = (sum(health_factors) / len(health_factors)) * 100
        else:
            stats['browser_health_score'] = 0
