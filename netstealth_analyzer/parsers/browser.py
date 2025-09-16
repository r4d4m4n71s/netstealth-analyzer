"""
Browser log parser for NetStealth Analyzer.

This module parses browser console logs and debug output to detect
automation signatures, JavaScript errors, and stealth-related issues.
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import LogFormat


class BrowserLogParser:
    """Parser for browser console and Chrome debug logs."""
    
    def __init__(self):
        """Initialize browser log parser with patterns."""
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
            'service_domains': re.compile(r'(link\.example\.com|offer\.example\.com|login\.example\.com|api\.example\.com)'),
            'service_api': re.compile(r'service.*?api|api.*?service', re.IGNORECASE),
            'oauth_flow': re.compile(r'oauth|authorize|token.*?exchange', re.IGNORECASE),
            'player_errors': re.compile(r'player.*?error|playback.*?error|audio.*?error', re.IGNORECASE),
        }
    
    def parse(self, log_path: Path) -> Dict[str, Any]:
        """
        Parse browser log file.
        
        Args:
            log_path: Path to browser log file
            
        Returns:
            Dict containing parsed data categorized by type
        """
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            raise ValueError(f"Failed to read browser log file {log_path}: {e}")
        
        lines = content.split('\n')
        
        # Determine log format from filename
        log_format = self._detect_browser_log_format(log_path)
        
        parsed_data = {
            'format': log_format.value,
            'source_file': str(log_path),
            'line_count': len(lines),
            'console_logs': [],
            'javascript_errors': [],
            'network_errors': [],
            'security_issues': [],
            'detection_events': [],
            'service_events': [],
            'browser_events': [],
            'errors': [],
            'timeline': [],
            'statistics': {
                'total_log_entries': 0,
                'javascript_errors': 0,
                'detection_attempts': 0,
                'service_related_events': 0,
                'security_violations': 0,
            }
        }
        
        # Parse line by line
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            # Extract timestamp and log level
            timestamp = self._extract_timestamp(line)
            log_level = self._extract_log_level(line)
            
            # Parse different types of log entries
            self._parse_console_logs(line, line_num, timestamp, log_level, parsed_data)
            self._parse_javascript_errors(line, line_num, timestamp, log_level, parsed_data)
            self._parse_network_errors(line, line_num, timestamp, log_level, parsed_data)
            self._parse_security_issues(line, line_num, timestamp, log_level, parsed_data)
            self._parse_detection_events(line, line_num, timestamp, log_level, parsed_data)
            self._parse_service_events(line, line_num, timestamp, log_level, parsed_data)
            self._parse_browser_events(line, line_num, timestamp, log_level, parsed_data)
            
            # Add to timeline
            timeline_entry = {
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'content': line.strip()[:250],  # Truncate very long lines
                'event_type': self._classify_browser_line(line),
                'is_service_related': bool(self.service_patterns['service_domains'].search(line)),
                'is_detection_related': any(pattern.search(line) for pattern in self.detection_patterns.values()),
                'is_error': log_level in ['ERROR', 'SEVERE', 'FATAL'] or 'error' in line.lower(),
            }
            parsed_data['timeline'].append(timeline_entry)
            parsed_data['statistics']['total_log_entries'] += 1
        
        # Calculate final statistics
        self._calculate_browser_statistics(parsed_data)
        
        return parsed_data
    
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
    
    def _parse_console_logs(self, line: str, line_num: int, timestamp: Optional[str],
                          log_level: str, data: Dict) -> None:
        """Parse console.log statements."""
        if self.patterns['console_log'].search(line):
            console_entry = {
                'message': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'console_method': self._extract_console_method(line),
                'is_service_related': bool(self.service_patterns['service_domains'].search(line)),
                'is_detection_related': any(pattern.search(line) for pattern in self.detection_patterns.values())
            }
            data['console_logs'].append(console_entry)
    
    def _parse_javascript_errors(self, line: str, line_num: int, timestamp: Optional[str],
                               log_level: str, data: Dict) -> None:
        """Parse JavaScript errors."""
        if (self.patterns['javascript_error'].search(line) or 
            log_level == 'ERROR' and ('script' in line.lower() or 'js' in line.lower())):
            
            js_error = {
                'error_message': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'error_type': self._classify_js_error(line),
                'source_url': self._extract_source_url(line),
                'is_service_related': bool(self.service_patterns['service_domains'].search(line)),
                'is_critical': 'uncaught' in line.lower() or 'unhandled' in line.lower(),
            }
            data['javascript_errors'].append(js_error)
            data['statistics']['javascript_errors'] += 1
    
    def _parse_network_errors(self, line: str, line_num: int, timestamp: Optional[str],
                            log_level: str, data: Dict) -> None:
        """Parse network-related errors."""
        if self.patterns['network_error'].search(line):
            network_error = {
                'error_message': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'error_code': self._extract_error_code(line),
                'url': self._extract_source_url(line),
                'is_service_related': bool(self.service_patterns['service_domains'].search(line)),
                'is_timeout': 'timeout' in line.lower(),
                'is_connection_error': 'connection' in line.lower() or 'refused' in line.lower(),
            }
            data['network_errors'].append(network_error)
    
    def _parse_security_issues(self, line: str, line_num: int, timestamp: Optional[str],
                             log_level: str, data: Dict) -> None:
        """Parse security-related issues."""
        if self.patterns['security_error'].search(line):
            security_issue = {
                'issue_description': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'issue_type': self._classify_security_issue(line),
                'source_url': self._extract_source_url(line),
                'is_service_related': bool(self.service_patterns['service_domains'].search(line)),
                'severity': self._assess_security_severity(line),
            }
            data['security_issues'].append(security_issue)
            data['statistics']['security_violations'] += 1
    
    def _parse_detection_events(self, line: str, line_num: int, timestamp: Optional[str],
                              log_level: str, data: Dict) -> None:
        """Parse automation/bot detection events."""
        detected_patterns = []
        for pattern_name, pattern in self.detection_patterns.items():
            if pattern.search(line):
                detected_patterns.append(pattern_name)
        
        if detected_patterns:
            detection_event = {
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
            data['detection_events'].append(detection_event)
            data['statistics']['detection_attempts'] += 1
    
    def _parse_service_events(self, line: str, line_num: int, timestamp: Optional[str],
                          log_level: str, data: Dict) -> None:
        """Parse service-specific events."""
        if any(pattern.search(line) for pattern in self.service_patterns.values()):
            service_event = {
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
            data['service_events'].append(service_event)
            data['statistics']['service_related_events'] += 1
    
    def _parse_browser_events(self, line: str, line_num: int, timestamp: Optional[str],
                            log_level: str, data: Dict) -> None:
        """Parse general browser events."""
        # Capture important browser events that don't fit other categories
        browser_keywords = ['navigate', 'load', 'unload', 'resize', 'focus', 'blur']
        
        if any(keyword in line.lower() for keyword in browser_keywords):
            browser_event = {
                'event_description': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'log_level': log_level,
                'event_type': self._classify_browser_event(line),
                'is_navigation': 'navigate' in line.lower() or 'load' in line.lower(),
                'is_user_interaction': any(word in line.lower() for word in ['click', 'focus', 'blur']),
            }
            data['browser_events'].append(browser_event)
    
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
    
    def _classify_browser_line(self, line: str) -> str:
        """Classify browser log line by type."""
        if self.patterns['console_log'].search(line):
            return 'console_log'
        elif self.patterns['javascript_error'].search(line):
            return 'javascript_error'
        elif self.patterns['network_error'].search(line):
            return 'network_error'
        elif self.patterns['security_error'].search(line):
            return 'security_issue'
        elif any(pattern.search(line) for pattern in self.detection_patterns.values()):
            return 'detection_event'
        elif any(pattern.search(line) for pattern in self.service_patterns.values()):
            return 'service_event'
        else:
            return 'general'
    
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
    
    def _calculate_browser_statistics(self, data: Dict) -> None:
        """Calculate final browser parsing statistics."""
        stats = data['statistics']
        
        # Calculate error rates
        total_entries = stats['total_log_entries']
        if total_entries > 0:
            stats['error_rate'] = (stats['javascript_errors'] / total_entries) * 100
            stats['service_event_percentage'] = (stats['service_related_events'] / total_entries) * 100
            stats['detection_attempt_rate'] = (stats['detection_attempts'] / total_entries) * 100
        else:
            stats['error_rate'] = 0
            stats['service_event_percentage'] = 0
            stats['detection_attempt_rate'] = 0
        
        # Count events by severity
        stats['high_severity_events'] = len([
            *[e for e in data['javascript_errors'] if e.get('is_critical')],
            *[e for e in data['security_issues'] if e.get('severity') == 'high'],
            *[e for e in data['detection_events'] if e.get('risk_level') == 'high']
        ])
        
        # Count unique detection types
        all_detection_types = set()
        for event in data['detection_events']:
            all_detection_types.update(event.get('detection_types', []))
        stats['unique_detection_types'] = len(all_detection_types)
        
        # Service-specific metrics
        stats['service_api_events'] = len([e for e in data['service_events'] 
                                         if e.get('is_api_related')])
        stats['service_oauth_events'] = len([e for e in data['service_events'] 
                                           if e.get('is_oauth_related')])
        stats['service_player_errors'] = len([e for e in data['service_events'] 
                                            if e.get('is_player_error')])
        
        # Network error analysis
        stats['network_errors'] = len(data['network_errors'])
        stats['timeout_errors'] = len([e for e in data['network_errors'] 
                                     if e.get('is_timeout')])
        stats['connection_errors'] = len([e for e in data['network_errors'] 
                                        if e.get('is_connection_error')])
        
        # Browser health score
        health_factors = [
            max(0.0, 1.0 - (stats['error_rate'] / 100.0)),  # Lower error rate is better
            max(0.0, 1.0 - (stats['detection_attempt_rate'] / 100.0)),  # Lower detection rate is better
            max(0.0, 1.0 - (stats['high_severity_events'] / max(total_entries, 1))),  # Fewer severe events is better
            1.0 if stats['service_related_events'] > 0 else 0.5,  # Having service events indicates activity
        ]
        stats['browser_health_score'] = (sum(health_factors) / len(health_factors)) * 100
