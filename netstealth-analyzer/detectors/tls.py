"""
TLS fingerprint detector for TIDAL Stealth Analyzer.

This module detects TLS fingerprint issues, certificate problems,
and handshake failures that could compromise stealth operations.
"""

from typing import Any, Dict, List
from datetime import datetime

from ..models import AnalysisConfig, CriticalIssue, IssueCategory, SeverityLevel


class TLSDetector:
    """Detector for TLS fingerprint and certificate issues."""
    
    def __init__(self, config: AnalysisConfig):
        """Initialize TLS detector with configuration."""
        self.config = config
        
        # TLS issue patterns and severity mappings
        self.tls_issues = {
            'handshake_failed': {
                'severity': SeverityLevel.CRITICAL,
                'impact_score': 90,
                'recommendation': 'Update undetected-chromedriver to latest version',
                'code_fix': 'uc.Chrome(version_main=120, use_subprocess=True)'
            },
            'certificate_error': {
                'severity': SeverityLevel.HIGH,
                'impact_score': 80,
                'recommendation': 'Check certificate installation and trust store',
                'code_fix': 'Reinstall mitmproxy certificate in system trust store'
            },
            'tls_version_mismatch': {
                'severity': SeverityLevel.MEDIUM,
                'impact_score': 60,
                'recommendation': 'Configure TLS version consistency',
                'code_fix': 'Set TLS min/max versions in Chrome options'
            },
            'cipher_suite_mismatch': {
                'severity': SeverityLevel.MEDIUM,
                'impact_score': 55,
                'recommendation': 'Configure cipher suite compatibility',
                'code_fix': 'Match cipher suites between browser and proxy'
            },
            'ja3_fingerprint_detected': {
                'severity': SeverityLevel.CRITICAL,
                'impact_score': 95,
                'recommendation': 'Use JA3 randomization or spoofing',
                'code_fix': 'Implement JA3 fingerprint randomization'
            }
        }
    
    def detect(self, parsed_data: Dict[str, Any]) -> List[CriticalIssue]:
        """
        Detect TLS-related issues from parsed log data.
        
        Args:
            parsed_data: Combined parsed data from all sources
            
        Returns:
            List of critical TLS issues found
        """
        issues = []
        
        # Extract TLS events from all sources
        all_tls_events = self._extract_tls_events(parsed_data)
        
        # Run detection methods
        issues.extend(self._detect_handshake_failures(all_tls_events))
        issues.extend(self._detect_certificate_issues(all_tls_events))
        issues.extend(self._detect_version_mismatches(all_tls_events))
        issues.extend(self._detect_cipher_issues(all_tls_events))
        issues.extend(self._detect_fingerprint_issues(all_tls_events, parsed_data))
        
        return issues
    
    def _extract_tls_events(self, parsed_data: Dict[str, Any]) -> List[Dict]:
        """Extract all TLS events from parsed sources."""
        all_events = []
        
        # Get TLS events from each source
        for source_data in parsed_data.get('sources', []):
            source_format = source_data.get('format', '')
            source_events = source_data.get('data', {}).get('tls_events', [])
            
            # Add source context to events
            for event in source_events:
                event['source_format'] = source_format
                event['source_path'] = source_data.get('path', '')
            
            all_events.extend(source_events)
        
        # Also check top-level tls_events
        all_events.extend(parsed_data.get('tls_events', []))
        
        return all_events
    
    def _detect_handshake_failures(self, tls_events: List[Dict]) -> List[CriticalIssue]:
        """Detect TLS handshake failures."""
        issues = []
        
        handshake_failures = []
        for event in tls_events:
            event_type = event.get('type', '')
            description = event.get('error_description', '').lower()
            
            if (event_type == 'tls_error' or 
                'handshake' in description and 'failed' in description):
                handshake_failures.append(event)
        
        if handshake_failures:
            issue_config = self.tls_issues['handshake_failed']
            
            # Group by server for detailed reporting
            server_failures = {}
            for failure in handshake_failures:
                server = failure.get('server', 'unknown')
                if server not in server_failures:
                    server_failures[server] = []
                server_failures[server].append(failure)
            
            for server, failures in server_failures.items():
                is_tidal = any(failure.get('is_tidal', False) for failure in failures)
                
                issue = CriticalIssue(
                    id=f"TLS_HANDSHAKE_FAILED_{server.replace('.', '_').upper()}",
                    category=IssueCategory.TLS_FINGERPRINT,
                    severity=issue_config['severity'],
                    title=f"TLS Handshake Failed - {server}",
                    description=f"TLS handshake failed for {server} ({len(failures)} occurrences). "
                               f"This indicates potential TLS fingerprint detection or certificate issues.",
                    location=server,
                    timestamp=datetime.now(),
                    recommendation=issue_config['recommendation'],
                    code_fix=issue_config['code_fix'],
                    impact_score=issue_config['impact_score'] + (10 if is_tidal else 0),
                    raw_data={'failures': failures[:3]}  # Include first 3 failures
                )
                issues.append(issue)
        
        return issues
    
    def _detect_certificate_issues(self, tls_events: List[Dict]) -> List[CriticalIssue]:
        """Detect certificate-related issues."""
        issues = []
        
        cert_issues = []
        for event in tls_events:
            description = event.get('error_description', '').lower()
            
            if any(cert_keyword in description for cert_keyword in 
                   ['certificate', 'cert', 'ssl', 'untrusted', 'invalid']):
                cert_issues.append(event)
        
        if cert_issues:
            issue_config = self.tls_issues['certificate_error']
            
            # Analyze certificate issue types
            issue_types = set()
            for cert_issue in cert_issues:
                description = cert_issue.get('error_description', '').lower()
                if 'untrusted' in description or 'invalid' in description:
                    issue_types.add('untrusted_certificate')
                elif 'expired' in description:
                    issue_types.add('expired_certificate')
                elif 'hostname' in description or 'name' in description:
                    issue_types.add('hostname_mismatch')
                else:
                    issue_types.add('general_certificate_error')
            
            issue = CriticalIssue(
                id="TLS_CERTIFICATE_ISSUES",
                category=IssueCategory.TLS_FINGERPRINT,
                severity=issue_config['severity'],
                title="TLS Certificate Issues Detected",
                description=f"Certificate issues detected: {', '.join(issue_types)}. "
                           f"Total occurrences: {len(cert_issues)}. "
                           f"This may indicate mitmproxy certificate trust issues.",
                timestamp=datetime.now(),
                recommendation=issue_config['recommendation'],
                code_fix=issue_config['code_fix'],
                impact_score=issue_config['impact_score'],
                raw_data={'issue_types': list(issue_types), 'issues': cert_issues[:5]}
            )
            issues.append(issue)
        
        return issues
    
    def _detect_version_mismatches(self, tls_events: List[Dict]) -> List[CriticalIssue]:
        """Detect TLS version inconsistencies."""
        issues = []
        
        # Collect TLS versions used
        versions_by_server = {}
        for event in tls_events:
            if event.get('tls_version'):
                server = event.get('server', 'unknown')
                version = event.get('tls_version')
                
                if server not in versions_by_server:
                    versions_by_server[server] = set()
                versions_by_server[server].add(version)
        
        # Look for servers using multiple TLS versions (potential inconsistency)
        inconsistent_servers = []
        for server, versions in versions_by_server.items():
            if len(versions) > 1:
                inconsistent_servers.append({
                    'server': server,
                    'versions': list(versions)
                })
        
        if inconsistent_servers:
            issue_config = self.tls_issues['tls_version_mismatch']
            
            issue = CriticalIssue(
                id="TLS_VERSION_INCONSISTENCY",
                category=IssueCategory.TLS_FINGERPRINT,
                severity=issue_config['severity'],
                title="TLS Version Inconsistency Detected",
                description=f"Inconsistent TLS versions detected across {len(inconsistent_servers)} servers. "
                           f"This may indicate fingerprint inconsistencies that could be detected.",
                timestamp=datetime.now(),
                recommendation=issue_config['recommendation'],
                code_fix=issue_config['code_fix'],
                impact_score=issue_config['impact_score'],
                raw_data={'inconsistent_servers': inconsistent_servers}
            )
            issues.append(issue)
        
        return issues
    
    def _detect_cipher_issues(self, tls_events: List[Dict]) -> List[CriticalIssue]:
        """Detect cipher suite issues."""
        issues = []
        
        # Collect cipher suites used
        cipher_usage = {}
        for event in tls_events:
            cipher = event.get('cipher_suite')
            if cipher:
                if cipher not in cipher_usage:
                    cipher_usage[cipher] = 0
                cipher_usage[cipher] += 1
        
        # Check for weak or unusual cipher suites
        weak_ciphers = []
        for cipher, count in cipher_usage.items():
            cipher_lower = cipher.lower()
            if any(weak in cipher_lower for weak in ['rc4', 'des', 'md5', 'sha1']):
                weak_ciphers.append({'cipher': cipher, 'usage_count': count})
        
        if weak_ciphers:
            issue_config = self.tls_issues['cipher_suite_mismatch']
            
            issue = CriticalIssue(
                id="TLS_WEAK_CIPHER_SUITES",
                category=IssueCategory.TLS_FINGERPRINT,
                severity=issue_config['severity'],
                title="Weak Cipher Suites Detected",
                description=f"Weak cipher suites in use: {[c['cipher'] for c in weak_ciphers]}. "
                           f"These may be flagged by security scanners and detection systems.",
                timestamp=datetime.now(),
                recommendation=issue_config['recommendation'],
                code_fix=issue_config['code_fix'],
                impact_score=issue_config['impact_score'],
                raw_data={'weak_ciphers': weak_ciphers}
            )
            issues.append(issue)
        
        return issues
    
    def _detect_fingerprint_issues(self, tls_events: List[Dict], parsed_data: Dict) -> List[CriticalIssue]:
        """Detect TLS fingerprinting attempts and issues."""
        issues = []
        
        # Look for JA3 fingerprinting indicators in browser logs
        browser_events = []
        for source_data in parsed_data.get('sources', []):
            if source_data.get('format', '') in ['browser_console', 'chrome_debug']:
                detection_events = source_data.get('data', {}).get('detection_events', [])
                for event in detection_events:
                    if 'tls_fingerprint' in event.get('detection_types', []):
                        browser_events.append(event)
        
        if browser_events:
            issue_config = self.tls_issues['ja3_fingerprint_detected']
            
            issue = CriticalIssue(
                id="TLS_FINGERPRINT_DETECTED",
                category=IssueCategory.TLS_FINGERPRINT,
                severity=issue_config['severity'],
                title="TLS Fingerprinting Detected",
                description=f"TLS fingerprinting attempts detected in browser logs ({len(browser_events)} events). "
                           f"Services may be analyzing JA3 signatures or other TLS characteristics.",
                timestamp=datetime.now(),
                recommendation=issue_config['recommendation'],
                code_fix=issue_config['code_fix'],
                impact_score=issue_config['impact_score'],
                raw_data={'detection_events': browser_events[:3]}
            )
            issues.append(issue)
        
        return issues
