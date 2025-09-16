"""
Proxy detection detector for Stealth Analyzer.

This module detects proxy usage indicators, header leakage,
and other signs that could reveal proxy usage to target services.
"""

from typing import Any, Dict, List
from datetime import datetime

from ..models import AnalysisConfig, CriticalIssue, IssueCategory, SeverityLevel


class ProxyDetector:
    """Detector for proxy usage indicators and leakage."""
    
    def __init__(self, config: AnalysisConfig):
        """Initialize proxy detector with configuration."""
        self.config = config
        self.target_geography = config.target_geography
        
        # Proxy detection patterns and severity mappings
        self.proxy_issues = {
            'proxy_headers_exposed': {
                'severity': SeverityLevel.CRITICAL,
                'impact_score': 95,
                'recommendation': 'Configure mitmproxy to strip proxy headers',
                'code_fix': 'Use mitmproxy script to remove X-Forwarded-For, Via headers'
            },
            'ip_mismatch_detected': {
                'severity': SeverityLevel.HIGH,
                'impact_score': 85,
                'recommendation': 'Ensure IP consistency across all requests',
                'code_fix': 'Check proxy configuration and exit IP stability'
            },
            'proxy_user_agent': {
                'severity': SeverityLevel.MEDIUM,
                'impact_score': 70,
                'recommendation': 'Use consistent browser user agent strings',
                'code_fix': 'Set user_agent in Chrome options to match real browser'
            },
            'unusual_routing_pattern': {
                'severity': SeverityLevel.MEDIUM,
                'impact_score': 60,
                'recommendation': 'Review proxy routing configuration',
                'code_fix': 'Optimize proxy chain to reduce suspicious patterns'
            },
            'geo_inconsistency': {
                'severity': SeverityLevel.HIGH,
                'impact_score': 80,
                'recommendation': 'Ensure geographic consistency in all requests',
                'code_fix': 'Use proxy servers from same geographic region'
            }
        }
        
        # Known proxy-revealing headers
        self.proxy_headers = [
            'X-Forwarded-For', 'X-Real-IP', 'Via', 'X-Proxy-Authorization',
            'Proxy-Authorization', 'X-Forwarded-Proto', 'X-Forwarded-Host',
            'X-Forwarded-Server', 'X-ProxyUser-Ip', 'Client-IP'
        ]
    
    def detect(self, parsed_data: Dict[str, Any]) -> List[CriticalIssue]:
        """
        Detect proxy-related issues from parsed log data.
        
        Args:
            parsed_data: Combined parsed data from all sources
            
        Returns:
            List of critical proxy issues found
        """
        issues = []
        
        # Extract proxy events from all sources
        all_proxy_events = self._extract_proxy_events(parsed_data)
        all_requests = self._extract_all_requests(parsed_data)
        
        # Run detection methods
        issues.extend(self._detect_header_leakage(all_proxy_events, all_requests))
        issues.extend(self._detect_ip_inconsistencies(parsed_data))
        issues.extend(self._detect_user_agent_issues(all_requests))
        issues.extend(self._detect_routing_anomalies(parsed_data))
        issues.extend(self._detect_geographic_inconsistencies(parsed_data))
        
        return issues
    
    def _extract_proxy_events(self, parsed_data: Dict[str, Any]) -> List[Dict]:
        """Extract all proxy events from parsed sources."""
        all_events = []
        
        # Get proxy events from each source
        for source_data in parsed_data.get('sources', []):
            source_format = source_data.get('format', '')
            source_events = source_data.get('data', {}).get('proxy_events', [])
            
            # Add source context to events
            for event in source_events:
                event['source_format'] = source_format
                event['source_path'] = source_data.get('path', '')
            
            all_events.extend(source_events)
        
        # Also check top-level proxy_events
        all_events.extend(parsed_data.get('proxy_events', []))
        
        return all_events
    
    def _extract_all_requests(self, parsed_data: Dict[str, Any]) -> List[Dict]:
        """Extract all HTTP requests from parsed sources."""
        all_requests = []
        
        # Get requests from each source
        for source_data in parsed_data.get('sources', []):
            source_requests = source_data.get('data', {}).get('requests', [])
            
            # Add source context to requests
            for request in source_requests:
                request['source_format'] = source_data.get('format', '')
                request['source_path'] = source_data.get('path', '')
            
            all_requests.extend(source_requests)
        
        # Also check top-level requests
        all_requests.extend(parsed_data.get('requests', []))
        
        return all_requests
    
    def _detect_header_leakage(self, proxy_events: List[Dict], requests: List[Dict]) -> List[CriticalIssue]:
        """Detect proxy headers being exposed to target services."""
        issues = []
        
        # Find proxy header exposures
        header_exposures = []
        
        # Check proxy events for header detection
        for event in proxy_events:
            event_type = event.get('type', '')
            if event_type in ['proxy_header_detected', 'proxy_headers_detected']:
                header_exposures.append(event)
        
        # Check requests for proxy headers
        for request in requests:
            if request.get('has_proxy_headers'):
                headers = request.get('headers', [])
                exposed_headers = []
                
                for header in headers:
                    header_name = header.get('name', '').lower()
                    if any(proxy_header.lower() in header_name for proxy_header in self.proxy_headers):
                        exposed_headers.append(header)
                
                if exposed_headers:
                    header_exposures.append({
                        'type': 'request_proxy_headers',
                        'url': request.get('url', ''),
                        'domain': request.get('domain', ''),
                        'exposed_headers': exposed_headers,
                        'is_service': request.get('is_service', False)
                    })
        
        if header_exposures:
            issue_config = self.proxy_issues['proxy_headers_exposed']
            
            # Analyze exposure patterns
            service_exposures = [e for e in header_exposures if e.get('is_service') or
                               any('example.com' in str(e.get(key, '')) for key in ['url', 'domain'])]
            
            # Count unique header types exposed
            exposed_header_types = set()
            for exposure in header_exposures:
                if 'exposed_headers' in exposure:
                    for header in exposure['exposed_headers']:
                        exposed_header_types.add(header.get('name', ''))
                elif 'request_headers' in exposure:
                    for header in exposure['request_headers']:
                        exposed_header_types.add(header.get('name', ''))
            
            issue = CriticalIssue(
                id="PROXY_HEADERS_EXPOSED",
                category=IssueCategory.PROXY_DETECTION,
                severity=issue_config['severity'],
                title="Proxy Headers Exposed to Target Services",
                description=f"Proxy-revealing headers detected in {len(header_exposures)} requests. "
                           f"Headers exposed: {', '.join(exposed_header_types)}. "
                           f"Service requests affected: {len(service_exposures)}. "
                           f"This clearly indicates proxy usage to target services.",
                timestamp=datetime.now(),
                recommendation=issue_config['recommendation'],
                code_fix=issue_config['code_fix'],
                impact_score=min(100, issue_config['impact_score'] + (10 if service_exposures else 0)),
                raw_data={
                    'total_exposures': len(header_exposures),
                    'service_exposures': len(service_exposures),
                    'exposed_headers': list(exposed_header_types),
                    'sample_exposures': header_exposures[:3]
                }
            )
            issues.append(issue)
        
        return issues
    
    def _detect_ip_inconsistencies(self, parsed_data: Dict) -> List[CriticalIssue]:
        """Detect IP address inconsistencies that could reveal proxy usage."""
        issues = []
        
        # Extract exit IPs from POC logs
        exit_ips = []
        for source_data in parsed_data.get('sources', []):
            if source_data.get('format', '') == 'poc_execution':
                source_exit_ips = source_data.get('data', {}).get('exit_ips', [])
                exit_ips.extend(source_exit_ips)
        
        if len(exit_ips) > 1:
            # Check for IP changes during session
            unique_ips = list(set(ip['ip_address'] for ip in exit_ips))
            
            if len(unique_ips) > 1:
                issue_config = self.proxy_issues['ip_mismatch_detected']
                
                # Analyze IP change pattern
                ip_timeline = sorted(exit_ips, key=lambda x: x.get('timestamp', ''))
                ip_changes = []
                
                for i in range(1, len(ip_timeline)):
                    prev_ip = ip_timeline[i-1]['ip_address']
                    curr_ip = ip_timeline[i]['ip_address']
                    
                    if prev_ip != curr_ip:
                        ip_changes.append({
                            'from_ip': prev_ip,
                            'to_ip': curr_ip,
                            'timestamp': ip_timeline[i].get('timestamp'),
                            'detection_method': ip_timeline[i].get('detection_method')
                        })
                
                issue = CriticalIssue(
                    id="IP_ADDRESS_INCONSISTENCY",
                    category=IssueCategory.PROXY_DETECTION,
                    severity=issue_config['severity'],
                    title="Exit IP Address Inconsistency Detected",
                    description=f"Multiple exit IP addresses detected during session: {', '.join(unique_ips)}. "
                               f"IP changes: {len(ip_changes)} occurrences. "
                               f"This inconsistency could be flagged by anti-fraud systems.",
                    timestamp=datetime.now(),
                    recommendation=issue_config['recommendation'],
                    code_fix=issue_config['code_fix'],
                    impact_score=issue_config['impact_score'],
                    raw_data={
                        'unique_ips': unique_ips,
                        'ip_changes': ip_changes,
                        'total_detections': len(exit_ips)
                    }
                )
                issues.append(issue)
        
        return issues
    
    def _detect_user_agent_issues(self, requests: List[Dict]) -> List[CriticalIssue]:
        """Detect user agent inconsistencies or proxy-related user agents."""
        issues = []
        
        # Extract user agents from requests
        user_agents = set()
        proxy_related_uas = []
        
        for request in requests:
            headers = request.get('headers', [])
            for header in headers:
                if header.get('name', '').lower() == 'user-agent':
                    ua_value = header.get('value', '')
                    user_agents.add(ua_value)
                    
                    # Check for proxy-related indicators in user agent
                    ua_lower = ua_value.lower()
                    if any(proxy_indicator in ua_lower for proxy_indicator in 
                           ['proxy', 'mitmproxy', 'selenium', 'automation', 'bot']):
                        proxy_related_uas.append({
                            'user_agent': ua_value,
                            'url': request.get('url', ''),
                            'is_service': request.get('is_service', False)
                        })
        
        if proxy_related_uas:
            issue_config = self.proxy_issues['proxy_user_agent']
            
            service_affected = [ua for ua in proxy_related_uas if ua['is_service']]
            
            issue = CriticalIssue(
                id="PROXY_USER_AGENT_DETECTED",
                category=IssueCategory.PROXY_DETECTION,
                severity=issue_config['severity'],
                title="Proxy-Related User Agent Detected",
                description=f"User agents containing proxy indicators detected: {len(proxy_related_uas)} requests. "
                           f"Service requests affected: {len(service_affected)}. "
                           f"This clearly reveals automation/proxy usage.",
                timestamp=datetime.now(),
                recommendation=issue_config['recommendation'],
                code_fix=issue_config['code_fix'],
                impact_score=min(100, issue_config['impact_score'] + (15 if service_affected else 0)),
                raw_data={
                    'proxy_user_agents': [ua['user_agent'] for ua in proxy_related_uas],
                    'service_affected_count': len(service_affected)
                }
            )
            issues.append(issue)
        
        # Check for multiple user agents (inconsistency)
        elif len(user_agents) > 2:  # Allow some variation
            issue_config = self.proxy_issues['unusual_routing_pattern']
            
            issue = CriticalIssue(
                id="USER_AGENT_INCONSISTENCY",
                category=IssueCategory.PROXY_DETECTION,
                severity=SeverityLevel.LOW,
                title="Multiple User Agents Detected",
                description=f"Multiple different user agents detected: {len(user_agents)} unique strings. "
                           f"This inconsistency might be noticed by tracking systems.",
                timestamp=datetime.now(),
                recommendation="Use consistent user agent across all requests",
                code_fix="Set single user agent in Chrome options",
                impact_score=40,
                raw_data={'user_agents': list(user_agents)[:5]}  # First 5
            )
            issues.append(issue)
        
        return issues
    
    def _detect_routing_anomalies(self, parsed_data: Dict) -> List[CriticalIssue]:
        """Detect unusual network routing patterns."""
        issues = []
        
        # Analyze connection patterns from network traces
        connections = []
        for source_data in parsed_data.get('sources', []):
            source_connections = source_data.get('data', {}).get('connections', [])
            connections.extend(source_connections)
        
        if connections:
            # Look for rapid server switching or unusual patterns
            server_switches = []
            upstream_proxies = set()
            
            for conn in connections:
                if conn.get('is_upstream_proxy'):
                    upstream_proxies.add(conn.get('server_ip', ''))
                
                # Check for rapid switching between servers
                if len(connections) > 1:
                    # Simple heuristic: more than 3 upstream proxy IPs might be suspicious
                    if len(upstream_proxies) > 3:
                        server_switches.append(conn)
            
            if len(upstream_proxies) > 3:
                issue_config = self.proxy_issues['unusual_routing_pattern']
                
                issue = CriticalIssue(
                    id="UNUSUAL_ROUTING_PATTERN",
                    category=IssueCategory.PROXY_DETECTION,
                    severity=issue_config['severity'],
                    title="Unusual Network Routing Pattern",
                    description=f"Multiple upstream proxy servers detected: {len(upstream_proxies)} different IPs. "
                               f"Rapid proxy switching might be flagged by network analysis systems.",
                    timestamp=datetime.now(),
                    recommendation=issue_config['recommendation'],
                    code_fix=issue_config['code_fix'],
                    impact_score=issue_config['impact_score'],
                    raw_data={'upstream_proxies': list(upstream_proxies)}
                )
                issues.append(issue)
        
        return issues
    
    def _detect_geographic_inconsistencies(self, parsed_data: Dict) -> List[CriticalIssue]:
        """Detect geographic inconsistencies in requests."""
        issues = []
        
        # Extract geographic information from various sources
        geo_indicators = {}
        target_country = self.target_geography.country_name.lower()
        target_language = self.target_geography.language.lower()
        target_timezone = self.target_geography.timezone.lower()
        
        # Check for geo information in requests or logs
        for source_data in parsed_data.get('sources', []):
            source_format = source_data.get('format', '')
            
            if source_format == 'poc_execution':
                # Check exit IPs for geographic information
                exit_ips = source_data.get('data', {}).get('exit_ips', [])
                for exit_ip in exit_ips:
                    if exit_ip.get('is_target_geo_ip'):
                        geo_indicators['exit_ip_target_geo'] = True
                    else:
                        geo_indicators['exit_ip_non_target_geo'] = True
            
            elif source_format in ['har', 'mitmproxy']:
                # Check for timezone or location headers
                requests = source_data.get('data', {}).get('requests', [])
                for request in requests:
                    headers = request.get('headers', [])
                    for header in headers:
                        header_name = header.get('name', '').lower()
                        header_value = header.get('value', '').lower()
                        
                        # Check timezone consistency
                        if 'timezone' in header_name:
                            if target_timezone not in header_value:
                                geo_indicators['timezone_mismatch'] = True
                        
                        # Check language consistency
                        elif 'accept-language' in header_name:
                            expected_lang = target_language.split('-')[0]  # e.g., 'en' from 'en-US'
                            if expected_lang not in header_value:
                                geo_indicators['language_mismatch'] = True
        
        # Check for geographic inconsistencies
        inconsistencies = []
        if geo_indicators.get('exit_ip_target_geo') and geo_indicators.get('timezone_mismatch'):
            inconsistencies.append(f'{target_country} IP but non-{target_country} timezone')
        if geo_indicators.get('exit_ip_target_geo') and geo_indicators.get('language_mismatch'):
            inconsistencies.append(f'{target_country} IP but non-{target_language} language preference')
        if geo_indicators.get('exit_ip_non_target_geo'):
            inconsistencies.append(f'Non-{target_country} exit IP detected')
        
        if inconsistencies:
            issue_config = self.proxy_issues['geo_inconsistency']
            
            issue = CriticalIssue(
                id="GEOGRAPHIC_INCONSISTENCY",
                category=IssueCategory.PROXY_DETECTION,
                severity=issue_config['severity'],
                title="Geographic Inconsistency Detected",
                description=f"Geographic inconsistencies detected: {', '.join(inconsistencies)}. "
                           f"These inconsistencies could be flagged by geo-location verification systems.",
                timestamp=datetime.now(),
                recommendation=f"Ensure geographic consistency with target location ({target_country})",
                code_fix=f"Use proxy servers from {target_country} and set appropriate timezone/language headers",
                impact_score=issue_config['impact_score'],
                raw_data={
                    'inconsistencies': inconsistencies,
                    'geo_indicators': geo_indicators,
                    'target_geography': {
                        'country': target_country,
                        'language': target_language,
                        'timezone': target_timezone
                    }
                }
            )
            issues.append(issue)
        
        return issues
