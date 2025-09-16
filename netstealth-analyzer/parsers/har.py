"""
HAR (HTTP Archive) file parser for NetStealth Analyzer.

This module parses HAR files to extract HTTP request/response data,
timing information, and detect stealth-related issues.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..models import LogFormat


class HarParser:
    """Parser for HAR (HTTP Archive) files."""
    
    def __init__(self):
        """Initialize HAR parser."""
        # TIDAL-specific patterns for URL analysis
        self.tidal_domains = [
            'link.tidal.com',
            'offer.tidal.com', 
            'login.tidal.com',
            'api.tidal.com',
            'dd.tidal.com',
            'resources.tidal.com'
        ]
        
        # Proxy-revealing headers to detect
        self.proxy_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'Via',
            'X-Proxy-Authorization',
            'Proxy-Authorization',
            'X-Forwarded-Proto',
            'X-Forwarded-Host'
        ]
        
        # IP detection services
        self.ip_services = [
            'httpbin.org',
            'whatismyipaddress.com',
            'ipinfo.io',
            'iplocation.net',
            'api.ipify.org'
        ]
    
    def parse(self, har_path: Path) -> Dict[str, Any]:
        """
        Parse HAR file and extract network data.
        
        Args:
            har_path: Path to HAR file
            
        Returns:
            Dict containing parsed data categorized by type
        """
        try:
            with open(har_path, 'r', encoding='utf-8') as f:
                har_data = json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to read HAR file {har_path}: {e}")
        
        # Validate HAR structure
        if 'log' not in har_data:
            raise ValueError("Invalid HAR file: missing 'log' section")
        
        log_data = har_data['log']
        entries = log_data.get('entries', [])
        
        parsed_data = {
            'format': LogFormat.HAR.value,
            'source_file': str(har_path),
            'har_version': log_data.get('version', '1.2'),
            'creator': log_data.get('creator', {}),
            'browser': log_data.get('browser', {}),
            'pages': log_data.get('pages', []),
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
                'proxy_indicators': 0,
                'ip_detection_requests': 0,
            }
        }
        
        # Parse each entry (request/response pair)
        for entry_index, entry in enumerate(entries):
            self._parse_har_entry(entry, entry_index, parsed_data)
        
        # Calculate statistics
        self._calculate_har_statistics(parsed_data)
        
        return parsed_data
    
    def _parse_har_entry(self, entry: Dict[str, Any], index: int, data: Dict) -> None:
        """Parse individual HAR entry (request/response pair)."""
        request = entry.get('request', {})
        response = entry.get('response', {})
        timings = entry.get('timings', {})
        
        # Extract basic request information
        url = request.get('url', '')
        method = request.get('method', 'GET')
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Parse request
        request_data = {
            'index': index,
            'method': method,
            'url': url,
            'domain': domain,
            'path': parsed_url.path,
            'query_string': parsed_url.query,
            'http_version': request.get('httpVersion', ''),
            'headers': self._extract_headers(request.get('headers', [])),
            'cookies': self._extract_cookies(request.get('cookies', [])),
            'post_data': request.get('postData', {}),
            'header_size': request.get('headersSize', 0),
            'body_size': request.get('bodySize', 0),
            'timestamp': entry.get('startedDateTime'),
            
            # Analysis flags
            'is_tidal': self._is_tidal_domain(domain),
            'is_ip_detection': self._is_ip_detection_service(domain),
            'has_proxy_headers': self._has_proxy_headers(request.get('headers', [])),
            'is_oauth_related': self._is_oauth_related(url),
            'is_secure': parsed_url.scheme == 'https',
        }
        
        # Parse response
        response_data = {
            'index': index,
            'status': response.get('status', 0),
            'status_text': response.get('statusText', ''),
            'http_version': response.get('httpVersion', ''),
            'headers': self._extract_headers(response.get('headers', [])),
            'cookies': self._extract_cookies(response.get('cookies', [])),
            'content': response.get('content', {}),
            'redirect_url': response.get('redirectURL', ''),
            'header_size': response.get('headersSize', 0),
            'body_size': response.get('bodySize', 0),
            
            # Timing information
            'blocked': timings.get('blocked', -1),
            'dns': timings.get('dns', -1),
            'connect': timings.get('connect', -1),
            'send': timings.get('send', -1),
            'wait': timings.get('wait', -1),
            'receive': timings.get('receive', -1),
            'ssl': timings.get('ssl', -1),
            'total_time': sum(t for t in timings.values() if t > 0),
            
            # Analysis flags
            'is_success': 200 <= response.get('status', 0) < 300,
            'is_redirect': 300 <= response.get('status', 0) < 400,
            'is_client_error': 400 <= response.get('status', 0) < 500,
            'is_server_error': 500 <= response.get('status', 0) < 600,
            'has_proxy_response_headers': self._has_proxy_headers(response.get('headers', [])),
        }
        
        # Correlate request and response
        request_data['response_status'] = response_data['status']
        request_data['response_time'] = response_data['total_time']
        response_data['request_url'] = request_data['url']
        response_data['request_method'] = request_data['method']
        response_data['is_tidal'] = request_data['is_tidal']
        
        data['requests'].append(request_data)
        data['responses'].append(response_data)
        
        # Update statistics
        data['statistics']['total_requests'] += 1
        if response_data['is_success']:
            data['statistics']['successful_responses'] += 1
        if request_data['is_tidal']:
            data['statistics']['tidal_requests'] += 1
        if request_data['has_proxy_headers'] or response_data['has_proxy_response_headers']:
            data['statistics']['proxy_indicators'] += 1
        if request_data['is_ip_detection']:
            data['statistics']['ip_detection_requests'] += 1
        
        # Check for TLS events
        if timings.get('ssl', -1) > 0:
            tls_event = {
                'type': 'ssl_handshake',
                'domain': domain,
                'ssl_time': timings['ssl'],
                'connect_time': timings.get('connect', -1),
                'timestamp': entry.get('startedDateTime'),
                'index': index,
                'is_tidal': request_data['is_tidal'],
                'success': response_data['is_success']
            }
            data['tls_events'].append(tls_event)
        
        # Check for proxy indicators
        if request_data['has_proxy_headers'] or response_data['has_proxy_response_headers']:
            proxy_event = {
                'type': 'proxy_headers_detected',
                'url': url,
                'domain': domain,
                'request_headers': [h for h in request_data['headers'] if h['name'].lower() in [ph.lower() for ph in self.proxy_headers]],
                'response_headers': [h for h in response_data['headers'] if h['name'].lower() in [ph.lower() for ph in self.proxy_headers]],
                'timestamp': entry.get('startedDateTime'),
                'index': index,
                'detection_risk': 'high' if domain in self.tidal_domains else 'medium'
            }
            data['proxy_events'].append(proxy_event)
        
        # Check for errors
        if response_data['is_client_error'] or response_data['is_server_error']:
            error_event = {
                'type': 'http_error',
                'url': url,
                'domain': domain,
                'status': response_data['status'],
                'status_text': response_data['status_text'],
                'timestamp': entry.get('startedDateTime'),
                'index': index,
                'is_tidal': request_data['is_tidal'],
                'severity': 'high' if response_data['is_server_error'] else 'medium'
            }
            data['errors'].append(error_event)
        
        # Add to timeline
        timeline_entry = {
            'timestamp': entry.get('startedDateTime'),
            'index': index,
            'event_type': 'http_request',
            'method': method,
            'url': url[:100] + '...' if len(url) > 100 else url,
            'status': response_data['status'],
            'duration_ms': response_data['total_time'],
            'is_tidal_related': request_data['is_tidal'],
            'is_error': not response_data['is_success']
        }
        data['timeline'].append(timeline_entry)
        
        # Create connection entry
        connection_entry = {
            'type': 'http_connection',
            'domain': domain,
            'ip': self._extract_server_ip(response.get('headers', [])),
            'port': parsed_url.port or (443 if parsed_url.scheme == 'https' else 80),
            'is_secure': request_data['is_secure'],
            'timestamp': entry.get('startedDateTime'),
            'index': index,
            'connect_time': timings.get('connect', -1),
            'ssl_time': timings.get('ssl', -1),
            'is_tidal': request_data['is_tidal']
        }
        data['connections'].append(connection_entry)
    
    def _extract_headers(self, headers_list: List[Dict]) -> List[Dict]:
        """Extract and normalize headers."""
        normalized_headers = []
        for header in headers_list:
            normalized_headers.append({
                'name': header.get('name', ''),
                'value': header.get('value', ''),
                'comment': header.get('comment', '')
            })
        return normalized_headers
    
    def _extract_cookies(self, cookies_list: List[Dict]) -> List[Dict]:
        """Extract and normalize cookies."""
        normalized_cookies = []
        for cookie in cookies_list:
            normalized_cookies.append({
                'name': cookie.get('name', ''),
                'value': cookie.get('value', ''),
                'domain': cookie.get('domain', ''),
                'path': cookie.get('path', ''),
                'expires': cookie.get('expires', ''),
                'secure': cookie.get('secure', False),
                'httponly': cookie.get('httpOnly', False)
            })
        return normalized_cookies
    
    def _extract_server_ip(self, headers: List[Dict]) -> Optional[str]:
        """Extract server IP from headers if available."""
        for header in headers:
            name = header.get('name', '').lower()
            if name in ['server-ip', 'x-server-ip', 'x-real-ip']:
                return header.get('value', '')
        return None
    
    def _is_tidal_domain(self, domain: str) -> bool:
        """Check if domain is TIDAL-related."""
        return any(tidal_domain in domain for tidal_domain in self.tidal_domains)
    
    def _is_ip_detection_service(self, domain: str) -> bool:
        """Check if domain is an IP detection service."""
        return any(service in domain for service in self.ip_services)
    
    def _has_proxy_headers(self, headers: List[Dict]) -> bool:
        """Check if headers contain proxy-revealing information."""
        header_names = [h.get('name', '').lower() for h in headers]
        return any(proxy_header.lower() in header_names for proxy_header in self.proxy_headers)
    
    def _is_oauth_related(self, url: str) -> bool:
        """Check if URL is OAuth-related."""
        oauth_indicators = ['oauth', 'authorize', 'token', 'auth', 'login']
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in oauth_indicators)
    
    def _calculate_har_statistics(self, data: Dict) -> None:
        """Calculate final HAR parsing statistics."""
        stats = data['statistics']
        
        # Calculate success rates
        if stats['total_requests'] > 0:
            stats['success_rate'] = (stats['successful_responses'] / stats['total_requests']) * 100
        else:
            stats['success_rate'] = 0
        
        # Calculate TIDAL success rate
        tidal_responses = [r for r in data['responses'] if r.get('is_tidal')]
        if tidal_responses:
            successful_tidal = len([r for r in tidal_responses if r['is_success']])
            stats['tidal_success_rate'] = (successful_tidal / len(tidal_responses)) * 100
        else:
            stats['tidal_success_rate'] = 0
        
        # Count unique domains
        unique_domains = set()
        for req in data['requests']:
            if req.get('domain'):
                unique_domains.add(req['domain'])
        stats['unique_domains'] = len(unique_domains)
        
        # Count secure vs insecure requests
        secure_requests = len([r for r in data['requests'] if r.get('is_secure')])
        stats['secure_requests'] = secure_requests
        stats['insecure_requests'] = stats['total_requests'] - secure_requests
        
        # Calculate average response times
        response_times = [r.get('total_time', 0) for r in data['responses'] if r.get('total_time', 0) > 0]
        if response_times:
            stats['average_response_time'] = sum(response_times) / len(response_times)
            stats['max_response_time'] = max(response_times)
            stats['min_response_time'] = min(response_times)
        else:
            stats['average_response_time'] = 0
            stats['max_response_time'] = 0 
            stats['min_response_time'] = 0
        
        # Count errors by type
        client_errors = len([e for e in data['errors'] if e.get('type') == 'http_error' and 400 <= e.get('status', 0) < 500])
        server_errors = len([e for e in data['errors'] if e.get('type') == 'http_error' and 500 <= e.get('status', 0) < 600])
        
        stats['client_errors'] = client_errors
        stats['server_errors'] = server_errors
        
        # Count TLS handshake metrics
        tls_events = data.get('tls_events', [])
        if tls_events:
            ssl_times = [e.get('ssl_time', 0) for e in tls_events if e.get('ssl_time', 0) > 0]
            if ssl_times:
                stats['average_ssl_time'] = sum(ssl_times) / len(ssl_times)
                stats['max_ssl_time'] = max(ssl_times)
            else:
                stats['average_ssl_time'] = 0
                stats['max_ssl_time'] = 0
        else:
            stats['average_ssl_time'] = 0
            stats['max_ssl_time'] = 0
        
        # Proxy detection risk assessment
        total_tidal_requests = stats['tidal_requests']
        tidal_proxy_indicators = len([e for e in data['proxy_events'] 
                                    if e.get('detection_risk') == 'high'])
        
        if total_tidal_requests > 0:
            stats['proxy_detection_risk'] = (tidal_proxy_indicators / total_tidal_requests) * 100
        else:
            stats['proxy_detection_risk'] = 0
        
        # OAuth flow analysis
        oauth_requests = [r for r in data['requests'] if r.get('is_oauth_related')]
        oauth_responses = [r for r in data['responses'] if r.get('is_tidal') and 
                          any(oauth_req['index'] == r['index'] for oauth_req in oauth_requests)]
        
        stats['oauth_requests'] = len(oauth_requests)
        stats['oauth_success_rate'] = 0
        if oauth_responses:
            successful_oauth = len([r for r in oauth_responses if r['is_success']])
            stats['oauth_success_rate'] = (successful_oauth / len(oauth_responses)) * 100
        
        # IP detection analysis
        ip_detection_responses = [r for r in data['responses'] 
                                if any(req['index'] == r['index'] and req['is_ip_detection'] 
                                      for req in data['requests'])]
        
        stats['ip_detection_success'] = len([r for r in ip_detection_responses if r['is_success']])
        stats['ip_detection_attempts'] = len(ip_detection_responses)
