"""
POC execution log parser for NetStealth Analyzer.

This module parses logs from network stealth POC execution to extract
exit IP detection, OAuth flow results, and session execution details.
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import LogFormat


class PocExecutionParser:
    """Parser for POC execution logs from tidal_proxy_poc.py."""
    
    def __init__(self):
        """Initialize POC execution parser with patterns."""
        # Patterns for POC log entries
        self.patterns = {
            'timestamp': re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'),
            'log_level': re.compile(r'(DEBUG|INFO|WARNING|ERROR|CRITICAL)'),
            'exit_ip_detected': re.compile(r'EXIT_IP_DETECTED:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'),
            'httpbin_response': re.compile(r'mitmproxy test response:\s*(.+)'),
            'oauth_step': re.compile(r'OAuth.*?(success|failed|complete|redirect)', re.IGNORECASE),
            'tidal_login': re.compile(r'(login|auth).*?tidal', re.IGNORECASE),
            'proxy_connection': re.compile(r'proxy.*?connect|upstream.*?connect', re.IGNORECASE),
            'browser_startup': re.compile(r'browser.*?start|chrome.*?start', re.IGNORECASE),
            'error_pattern': re.compile(r'error|exception|failed|timeout', re.IGNORECASE),
            'success_pattern': re.compile(r'success|complete|ok|200', re.IGNORECASE),
        }
        
        # TIDAL-specific patterns
        self.tidal_patterns = {
            'tidal_urls': re.compile(r'(link\.tidal\.com|offer\.tidal\.com|login\.tidal\.com)'),
            'oauth_redirect': re.compile(r'redirect.*?tidal|tidal.*?redirect', re.IGNORECASE),
            'datadome_bypass': re.compile(r'datadome.*?bypass|bypass.*?datadome', re.IGNORECASE),
            'colombia_ip': re.compile(r'186\.84\.\d+\.\d+|colombia|CO\b', re.IGNORECASE),
            'geo_detection': re.compile(r'geo.*?detect|location.*?detect', re.IGNORECASE),
        }
    
    def parse(self, log_path: Path) -> Dict[str, Any]:
        """
        Parse POC execution log file.
        
        Args:
            log_path: Path to poc_execution.log file
            
        Returns:
            Dict containing parsed data categorized by type
        """
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            raise ValueError(f"Failed to read POC log file {log_path}: {e}")
        
        lines = content.split('\n')
        
        parsed_data = {
            'format': LogFormat.POC_EXECUTION.value,
            'source_file': str(log_path),
            'line_count': len(lines),
            'exit_ips': [],
            'oauth_events': [],
            'browser_events': [],
            'proxy_events': [],
            'tidal_events': [],
            'errors': [],
            'timeline': [],
            'session_info': {
                'start_time': None,
                'end_time': None,
                'duration_seconds': 0,
                'success': False,
            },
            'statistics': {
                'exit_ips_detected': 0,
                'oauth_steps_completed': 0,
                'errors_count': 0,
                'tidal_requests': 0,
                'colombia_ips_found': 0,
            }
        }
        
        # Parse line by line
        session_start = None
        session_end = None
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            # Extract timestamp and log level
            timestamp_match = self.patterns['timestamp'].search(line)
            timestamp = None
            if timestamp_match:
                timestamp_str = timestamp_match.group(1)
                try:
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    if session_start is None:
                        session_start = timestamp
                    session_end = timestamp
                except ValueError:
                    timestamp = None
            
            log_level_match = self.patterns['log_level'].search(line)
            log_level = log_level_match.group(1) if log_level_match else 'INFO'
            
            # Parse different types of events
            self._parse_exit_ips(line, line_num, timestamp, log_level, parsed_data)
            self._parse_oauth_events(line, line_num, timestamp, log_level, parsed_data)
            self._parse_browser_events(line, line_num, timestamp, log_level, parsed_data)
            self._parse_proxy_events(line, line_num, timestamp, log_level, parsed_data)
            self._parse_tidal_events(line, line_num, timestamp, log_level, parsed_data)
            self._parse_errors(line, line_num, timestamp, log_level, parsed_data)
            
            # Add to timeline
            timeline_entry = {
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'content': line.strip()[:300],  # Truncate very long lines
                'event_type': self._classify_poc_line(line),
                'is_tidal_related': bool(self.tidal_patterns['tidal_urls'].search(line)),
                'is_error': bool(self.patterns['error_pattern'].search(line)),
            }
            parsed_data['timeline'].append(timeline_entry)
        
        # Calculate session info
        if session_start and session_end:
            parsed_data['session_info']['start_time'] = session_start.isoformat()
            parsed_data['session_info']['end_time'] = session_end.isoformat()
            duration = (session_end - session_start).total_seconds()
            parsed_data['session_info']['duration_seconds'] = duration
            
            # Determine session success
            success_indicators = [
                len(parsed_data['exit_ips']) > 0,
                len(parsed_data['oauth_events']) > 0,
                parsed_data['statistics']['errors_count'] < 5,
                any('success' in str(event).lower() for event in parsed_data['oauth_events'])
            ]
            parsed_data['session_info']['success'] = sum(success_indicators) >= 2
        
        # Calculate final statistics
        self._calculate_poc_statistics(parsed_data)
        
        return parsed_data
    
    def _parse_exit_ips(self, line: str, line_num: int, timestamp: Optional[datetime], 
                       log_level: str, data: Dict) -> None:
        """Parse exit IP detection events."""
        # Direct EXIT_IP_DETECTED entries
        exit_ip_match = self.patterns['exit_ip_detected'].search(line)
        if exit_ip_match:
            detected_ip = exit_ip_match.group(1)
            exit_ip_event = {
                'ip_address': detected_ip,
                'detection_method': 'poc_enhanced_logging',
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'is_colombia_ip': bool(self.tidal_patterns['colombia_ip'].search(detected_ip)),
                'verification_source': 'EXIT_IP_DETECTED log entry'
            }
            data['exit_ips'].append(exit_ip_event)
            data['statistics']['exit_ips_detected'] += 1
            
            if exit_ip_event['is_colombia_ip']:
                data['statistics']['colombia_ips_found'] += 1
            return
        
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
                            'ip_address': origin_ip,
                            'detection_method': 'httpbin_test_response',
                            'timestamp': timestamp.isoformat() if timestamp else None,
                            'line_number': line_num,
                            'log_level': log_level,
                            'is_colombia_ip': bool(self.tidal_patterns['colombia_ip'].search(origin_ip)),
                            'verification_source': 'httpbin.org/ip response',
                            'raw_response': response_text[:200]  # First 200 chars
                        }
                        data['exit_ips'].append(exit_ip_event)
                        data['statistics']['exit_ips_detected'] += 1
                        
                        if exit_ip_event['is_colombia_ip']:
                            data['statistics']['colombia_ips_found'] += 1
                
            except json.JSONDecodeError:
                # Try regex extraction as fallback
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', response_text)
                if ip_match:
                    potential_ip = ip_match.group(1)
                    if self._is_valid_ip(potential_ip):
                        exit_ip_event = {
                            'ip_address': potential_ip,
                            'detection_method': 'httpbin_regex_extraction',
                            'timestamp': timestamp.isoformat() if timestamp else None,
                            'line_number': line_num,
                            'log_level': log_level,
                            'is_colombia_ip': bool(self.tidal_patterns['colombia_ip'].search(potential_ip)),
                            'verification_source': 'httpbin response (regex)',
                            'raw_response': response_text[:200]
                        }
                        data['exit_ips'].append(exit_ip_event)
                        data['statistics']['exit_ips_detected'] += 1
    
    def _parse_oauth_events(self, line: str, line_num: int, timestamp: Optional[datetime],
                          log_level: str, data: Dict) -> None:
        """Parse OAuth-related events."""
        if self.patterns['oauth_step'].search(line) or self.patterns['tidal_login'].search(line):
            oauth_event = {
                'event_description': line.strip(),
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'is_success': bool(self.patterns['success_pattern'].search(line)),
                'is_error': bool(self.patterns['error_pattern'].search(line)),
                'is_redirect': bool(self.tidal_patterns['oauth_redirect'].search(line)),
                'step_type': self._classify_oauth_step(line)
            }
            data['oauth_events'].append(oauth_event)
            
            if oauth_event['is_success']:
                data['statistics']['oauth_steps_completed'] += 1
    
    def _parse_browser_events(self, line: str, line_num: int, timestamp: Optional[datetime],
                            log_level: str, data: Dict) -> None:
        """Parse browser-related events."""
        if self.patterns['browser_startup'].search(line):
            browser_event = {
                'event_type': 'browser_startup',
                'event_description': line.strip(),
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'is_success': bool(self.patterns['success_pattern'].search(line)),
                'is_error': bool(self.patterns['error_pattern'].search(line)),
            }
            data['browser_events'].append(browser_event)
    
    def _parse_proxy_events(self, line: str, line_num: int, timestamp: Optional[datetime],
                          log_level: str, data: Dict) -> None:
        """Parse proxy-related events."""
        if self.patterns['proxy_connection'].search(line):
            proxy_event = {
                'event_type': 'proxy_connection',
                'event_description': line.strip(),
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'is_success': bool(self.patterns['success_pattern'].search(line)),
                'is_error': bool(self.patterns['error_pattern'].search(line)),
                'is_upstream': 'upstream' in line.lower(),
            }
            data['proxy_events'].append(proxy_event)
    
    def _parse_tidal_events(self, line: str, line_num: int, timestamp: Optional[datetime],
                          log_level: str, data: Dict) -> None:
        """Parse TIDAL-specific events."""
        if self.tidal_patterns['tidal_urls'].search(line):
            tidal_event = {
                'event_description': line.strip(),
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'url_accessed': self._extract_tidal_url(line),
                'is_oauth_related': bool(self.tidal_patterns['oauth_redirect'].search(line)),
                'is_datadome_related': bool(self.tidal_patterns['datadome_bypass'].search(line)),
                'is_success': bool(self.patterns['success_pattern'].search(line)),
            }
            data['tidal_events'].append(tidal_event)
            data['statistics']['tidal_requests'] += 1
    
    def _parse_errors(self, line: str, line_num: int, timestamp: Optional[datetime],
                     log_level: str, data: Dict) -> None:
        """Parse error events."""
        if (self.patterns['error_pattern'].search(line) or 
            log_level in ['ERROR', 'CRITICAL']):
            
            error_event = {
                'error_description': line.strip(),
                'timestamp': timestamp.isoformat() if timestamp else None,
                'line_number': line_num,
                'log_level': log_level,
                'error_type': self._classify_error_type(line),
                'is_critical': log_level == 'CRITICAL',
                'is_tidal_related': bool(self.tidal_patterns['tidal_urls'].search(line)),
            }
            data['errors'].append(error_event)
            data['statistics']['errors_count'] += 1
    
    def _classify_poc_line(self, line: str) -> str:
        """Classify POC log line by event type."""
        if self.patterns['exit_ip_detected'].search(line) or self.patterns['httpbin_response'].search(line):
            return 'exit_ip_detection'
        elif self.patterns['oauth_step'].search(line) or self.patterns['tidal_login'].search(line):
            return 'oauth_flow'
        elif self.patterns['browser_startup'].search(line):
            return 'browser_event'
        elif self.patterns['proxy_connection'].search(line):
            return 'proxy_event'
        elif self.tidal_patterns['tidal_urls'].search(line):
            return 'tidal_request'
        elif self.patterns['error_pattern'].search(line):
            return 'error'
        else:
            return 'general'
    
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
    
    def _extract_tidal_url(self, line: str) -> Optional[str]:
        """Extract TIDAL URL from log line."""
        url_match = self.tidal_patterns['tidal_urls'].search(line)
        if url_match:
            # Try to extract full URL
            url_start = line.find('http')
            if url_start != -1:
                # Find end of URL (space or end of line)
                url_end = line.find(' ', url_start)
                if url_end == -1:
                    url_end = len(line)
                return line[url_start:url_end].strip()
            else:
                return url_match.group(0)
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
    
    def _calculate_poc_statistics(self, data: Dict) -> None:
        """Calculate final POC parsing statistics."""
        stats = data['statistics']
        
        # Calculate success rate
        total_events = (len(data['oauth_events']) + len(data['browser_events']) + 
                       len(data['proxy_events']) + len(data['tidal_events']))
        
        if total_events > 0:
            successful_events = sum([
                len([e for e in data['oauth_events'] if e.get('is_success')]),
                len([e for e in data['browser_events'] if e.get('is_success')]),
                len([e for e in data['proxy_events'] if e.get('is_success')]),
                len([e for e in data['tidal_events'] if e.get('is_success')])
            ])
            stats['success_rate'] = (successful_events / total_events) * 100
        else:
            stats['success_rate'] = 0
        
        # Count unique detected IPs
        unique_ips = set(ip['ip_address'] for ip in data['exit_ips'])
        stats['unique_exit_ips'] = len(unique_ips)
        
        # Count Colombia IP percentage
        if stats['exit_ips_detected'] > 0:
            stats['colombia_ip_percentage'] = (stats['colombia_ips_found'] / stats['exit_ips_detected']) * 100
        else:
            stats['colombia_ip_percentage'] = 0
        
        # Count critical errors
        stats['critical_errors'] = len([e for e in data['errors'] if e.get('is_critical')])
        
        # OAuth completion rate
        oauth_attempts = len(data['oauth_events'])
        if oauth_attempts > 0:
            stats['oauth_completion_rate'] = (stats['oauth_steps_completed'] / oauth_attempts) * 100
        else:
            stats['oauth_completion_rate'] = 0
        
        # Session health score
        health_factors = [
            stats['success_rate'] / 100,
            1.0 if stats['exit_ips_detected'] > 0 else 0.0,
            1.0 if stats['colombia_ips_found'] > 0 else 0.0,
            max(0.0, 1.0 - (stats['critical_errors'] / 10.0)),  # Penalty for critical errors
            stats['oauth_completion_rate'] / 100
        ]
        stats['session_health_score'] = (sum(health_factors) / len(health_factors)) * 100
