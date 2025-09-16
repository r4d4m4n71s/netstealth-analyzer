"""
Mitmproxy log parser for TIDAL Stealth Analyzer.

This module parses mitmproxy debug logs to extract network connections,
requests, responses, TLS events, and proxy-related information.
"""

import re
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import LogFormat


class MitmproxyParser:
    """Parser for mitmproxy debug logs."""
    
    def __init__(self):
        """Initialize mitmproxy parser with regex patterns."""
        # Core patterns for log parsing  
        self.patterns = {
            'timestamp': re.compile(r'^\[(\d{2}:\d{2}:\d{2}\.\d{3})\]'),
            'client_connect': re.compile(r'\[(.*?)\] client connect'),
            'server_connect': re.compile(r'\[(.*?)\] server connect (.*?) \((.*?)\)'),
            'request': re.compile(r'Request: (GET|POST|PUT|DELETE|OPTIONS|HEAD) (.+)'),
            'response': re.compile(r'Response: (\d+) (.+)'),
            'tls_hello': re.compile(r'TLS Client Hello: \(\'(.*?)\', (\d+)\)'),
            'tls_error': re.compile(r'TLS.*?error|handshake.*?failed|certificate.*?error', re.IGNORECASE),
            'proxy_error': re.compile(r'(\d+) Forbidden|proxy.*?refused|upstream.*?error', re.IGNORECASE),
            'connection_error': re.compile(r'connection.*?failed|timeout|refused', re.IGNORECASE),
        }
        
        # TIDAL-specific patterns
        self.tidal_patterns = {
            'tidal_domains': re.compile(r'(link\.tidal\.com|offer\.tidal\.com|login\.tidal\.com|dd\.tidal\.com|api\.tidal\.com)'),
            'oauth_flow': re.compile(r'(authorize|oauth|token)', re.IGNORECASE),
            'datadome': re.compile(r'(captcha-delivery\.com|datadome|x-datadome)', re.IGNORECASE),
            'proxy_headers': re.compile(r'(X-Forwarded-For|X-Real-IP|Via|Proxy)', re.IGNORECASE),
            'ip_detection': re.compile(r'(httpbin\.org/ip|whatismyip|ipinfo\.io|iplocation)', re.IGNORECASE),
        }
    
    def parse(self, log_path: Path) -> Dict[str, Any]:
        """
        Parse mitmproxy debug log file.
        
        Args:
            log_path: Path to mitmproxy debug log file
            
        Returns:
            Dict containing parsed data categorized by type
        """
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            raise ValueError(f"Failed to read log file {log_path}: {e}")
        
        lines = content.split('\n')
        
        parsed_data = {
            'format': LogFormat.MITMPROXY.value,
            'source_file': str(log_path),
            'line_count': len(lines),
            'requests': [],
            'responses': [],
            'connections': [],
            'tls_events': [],
            'proxy_events': [],
            'errors': [],
            'timeline': [],
            'statistics': {
                'total_requests': 0,
                'successful_responses': 0,
                'tidal_requests': 0,
                'proxy_errors': 0,
                'tls_errors': 0,
            }
        }
        
        # Parse line by line
        current_context = {}
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            # Extract timestamp
            timestamp_match = self.patterns['timestamp'].search(line)
            timestamp = timestamp_match.group(1) if timestamp_match else None
            
            # Parse different log entry types
            self._parse_connections(line, line_num, timestamp, parsed_data, current_context)
            self._parse_requests(line, line_num, timestamp, parsed_data, current_context)
            self._parse_responses(line, line_num, timestamp, parsed_data, current_context)
            self._parse_tls_events(line, line_num, timestamp, parsed_data, current_context)
            self._parse_proxy_events(line, line_num, timestamp, parsed_data, current_context)
            self._parse_errors(line, line_num, timestamp, parsed_data, current_context)
            
            # Add to timeline
            if timestamp:
                timeline_entry = {
                    'timestamp': timestamp,
                    'line_number': line_num,
                    'event_type': self._classify_line(line),
                    'content': line.strip()[:200],  # Truncate long lines
                    'is_tidal_related': bool(self.tidal_patterns['tidal_domains'].search(line))
                }
                parsed_data['timeline'].append(timeline_entry)
        
        # Calculate final statistics
        self._calculate_statistics(parsed_data)
        
        return parsed_data
    
    def _parse_connections(self, line: str, line_num: int, timestamp: str, data: Dict, context: Dict) -> None:
        """Parse connection-related log entries."""
        # Client connections
        client_match = self.patterns['client_connect'].search(line)
        if client_match:
            client_id = client_match.group(1)
            connection = {
                'type': 'client_connect',
                'client_id': client_id,
                'timestamp': timestamp,
                'line_number': line_num,
                'source_ip': '[::1]',  # Default for mitmproxy
            }
            data['connections'].append(connection)
            context['current_client'] = client_id
            return
        
        # Server connections
        server_match = self.patterns['server_connect'].search(line)
        if server_match:
            client_id, server, ip = server_match.groups()
            connection = {
                'type': 'server_connect',
                'client_id': client_id,
                'server': server,
                'server_ip': ip,
                'timestamp': timestamp,
                'line_number': line_num,
                'is_tidal': bool(self.tidal_patterns['tidal_domains'].search(server)),
                'is_upstream_proxy': 'geo.iproyal.com' in server or 'proxy' in server.lower(),
                'upstream_proxy': ip if 'geo.iproyal.com' in server else None
            }
            data['connections'].append(connection)
            
            # Update context for request correlation
            context['current_server'] = server
            context['current_server_ip'] = ip
            return
    
    def _parse_requests(self, line: str, line_num: int, timestamp: str, data: Dict, context: Dict) -> None:
        """Parse HTTP request log entries."""
        request_match = self.patterns['request'].search(line)
        if request_match:
            method, url = request_match.groups()
            
            # Extract domain from URL
            domain = None
            if '://' in url:
                try:
                    domain = url.split('://')[1].split('/')[0]
                except IndexError:
                    domain = url
            
            request = {
                'method': method,
                'url': url,
                'domain': domain,
                'timestamp': timestamp,
                'line_number': line_num,
                'client_id': context.get('current_client'),
                'server': context.get('current_server'),
                'server_ip': context.get('current_server_ip'),
                'is_tidal': bool(self.tidal_patterns['tidal_domains'].search(url)),
                'is_oauth_related': bool(self.tidal_patterns['oauth_flow'].search(url)),
                'is_ip_detection': bool(self.tidal_patterns['ip_detection'].search(url)),
                'has_proxy_headers': bool(self.tidal_patterns['proxy_headers'].search(line)),
            }
            
            data['requests'].append(request)
            data['statistics']['total_requests'] += 1
            
            if request['is_tidal']:
                data['statistics']['tidal_requests'] += 1
            
            # Update context for response correlation
            context['last_request'] = request
    
    def _parse_responses(self, line: str, line_num: int, timestamp: str, data: Dict, context: Dict) -> None:
        """Parse HTTP response log entries."""
        response_match = self.patterns['response'].search(line)
        if response_match:
            status_code = int(response_match.group(1))
            status_text = response_match.group(2)
            
            response = {
                'status_code': status_code,
                'status_text': status_text,
                'timestamp': timestamp,
                'line_number': line_num,
                'client_id': context.get('current_client'),
                'server': context.get('current_server'),
                'is_success': 200 <= status_code < 300,
                'is_redirect': 300 <= status_code < 400,
                'is_client_error': 400 <= status_code < 500,
                'is_server_error': 500 <= status_code < 600,
            }
            
            # Correlate with last request if available
            if 'last_request' in context:
                last_req = context['last_request']
                response.update({
                    'request_url': last_req.get('url'),
                    'request_method': last_req.get('method'),
                    'is_tidal': last_req.get('is_tidal', False),
                    'is_oauth_related': last_req.get('is_oauth_related', False),
                })
            
            data['responses'].append(response)
            
            if response['is_success']:
                data['statistics']['successful_responses'] += 1
    
    def _parse_tls_events(self, line: str, line_num: int, timestamp: str, data: Dict, context: Dict) -> None:
        """Parse TLS-related log entries."""
        # TLS Client Hello
        hello_match = self.patterns['tls_hello'].search(line)
        if hello_match:
            server, port = hello_match.groups()
            tls_event = {
                'type': 'client_hello',
                'server': server,
                'port': int(port),
                'timestamp': timestamp,
                'line_number': line_num,
                'client_id': context.get('current_client'),
                'is_tidal': bool(self.tidal_patterns['tidal_domains'].search(server)),
            }
            data['tls_events'].append(tls_event)
            return
        
        # TLS Errors
        if self.patterns['tls_error'].search(line):
            tls_event = {
                'type': 'tls_error',
                'error_description': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'client_id': context.get('current_client'),
                'server': context.get('current_server'),
                'severity': 'critical' if any(word in line.lower() for word in ['failed', 'error']) else 'warning',
            }
            data['tls_events'].append(tls_event)
            data['statistics']['tls_errors'] += 1
    
    def _parse_proxy_events(self, line: str, line_num: int, timestamp: str, data: Dict, context: Dict) -> None:
        """Parse proxy-related log entries."""
        if self.patterns['proxy_error'].search(line):
            proxy_event = {
                'type': 'proxy_error',
                'error_description': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'client_id': context.get('current_client'),
                'server': context.get('current_server'),
                'is_forbidden': '403' in line or 'Forbidden' in line,
                'is_upstream_error': 'upstream' in line.lower(),
            }
            data['proxy_events'].append(proxy_event)
            data['statistics']['proxy_errors'] += 1
            return
        
        # Proxy header detection
        if self.tidal_patterns['proxy_headers'].search(line):
            proxy_event = {
                'type': 'proxy_header_detected',
                'header_info': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'client_id': context.get('current_client'),
                'potential_detection_risk': True,
            }
            data['proxy_events'].append(proxy_event)
    
    def _parse_errors(self, line: str, line_num: int, timestamp: str, data: Dict, context: Dict) -> None:
        """Parse general error log entries."""
        if self.patterns['connection_error'].search(line):
            error = {
                'type': 'connection_error',
                'error_description': line.strip(),
                'timestamp': timestamp,
                'line_number': line_num,
                'client_id': context.get('current_client'),
                'server': context.get('current_server'),
                'severity': 'high' if any(word in line.lower() for word in ['failed', 'timeout']) else 'medium',
            }
            data['errors'].append(error)
    
    def _classify_line(self, line: str) -> str:
        """Classify log line by type."""
        if self.patterns['client_connect'].search(line):
            return 'client_connect'
        elif self.patterns['server_connect'].search(line):
            return 'server_connect'
        elif self.patterns['request'].search(line):
            return 'http_request'
        elif self.patterns['response'].search(line):
            return 'http_response'
        elif self.patterns['tls_hello'].search(line) or self.patterns['tls_error'].search(line):
            return 'tls_event'
        elif self.patterns['proxy_error'].search(line) or self.tidal_patterns['proxy_headers'].search(line):
            return 'proxy_event'
        elif self.patterns['connection_error'].search(line):
            return 'error'
        else:
            return 'other'
    
    def _calculate_statistics(self, data: Dict) -> None:
        """Calculate final parsing statistics."""
        stats = data['statistics']
        
        # Calculate success rates
        total_responses = len(data['responses'])
        if total_responses > 0:
            stats['success_rate'] = (stats['successful_responses'] / total_responses) * 100
        else:
            stats['success_rate'] = 0
        
        # Count unique servers
        unique_servers = set()
        for conn in data['connections']:
            if conn.get('server'):
                unique_servers.add(conn['server'])
        stats['unique_servers'] = len(unique_servers)
        
        # Count TIDAL-specific metrics
        tidal_responses = [r for r in data['responses'] if r.get('is_tidal')]
        stats['tidal_success_rate'] = 0
        if tidal_responses:
            successful_tidal = len([r for r in tidal_responses if r['is_success']])
            stats['tidal_success_rate'] = (successful_tidal / len(tidal_responses)) * 100
        
        # Count OAuth flow completions
        oauth_requests = [r for r in data['requests'] if r.get('is_oauth_related')]
        oauth_responses = [r for r in data['responses'] if r.get('is_oauth_related')]
        stats['oauth_flow_requests'] = len(oauth_requests)
        stats['oauth_flow_responses'] = len(oauth_responses)
        
        # Count IP detection attempts
        ip_detection_requests = [r for r in data['requests'] if r.get('is_ip_detection')]
        stats['ip_detection_requests'] = len(ip_detection_requests)
        
        # Risk indicators
        stats['proxy_detection_risks'] = len([e for e in data['proxy_events'] 
                                            if e.get('potential_detection_risk')])
        stats['critical_tls_errors'] = len([e for e in data['tls_events'] 
                                          if e.get('severity') == 'critical'])
