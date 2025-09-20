"""
Proxy detection and leak detector.

This module detects proxy-related stealth issues including proxy leaks,
detection by target services, and proxy configuration problems with full async support.
"""

import time
from typing import Any, AsyncIterator, Dict, List, Optional, Set
from datetime import datetime, timezone
import re

from .base import BaseDetector, DetectionContext, DetectionResult
from ..models.issues import Issue, IssueEvidence, DetectionRule
from ..models.enums import SeverityLevel, IssueCategory, DetectionConfidence
from ..models.network import NetworkTrace


class ProxyDetector(BaseDetector):
    """
    Detector for proxy-related stealth issues.
    
    Analyzes network traces for proxy detection, IP leaks, proxy headers,
    and other indicators that proxy usage has been detected or compromised.
    """
    
    def __init__(self, event_bus=None, confidence_threshold=0.7):
        """Initialize Proxy detector."""
        super().__init__(event_bus, confidence_threshold)
        
        # Proxy detection indicators
        self.proxy_detection_patterns = [
            # Direct proxy detection messages
            r'proxy.*detected',
            r'using.*proxy',
            r'proxy.*blocked',
            r'proxy.*not.*allowed',
            # VPN/Proxy service detection
            r'vpn.*detected',
            r'datacenter.*ip',
            r'hosting.*provider',
            r'commercial.*proxy',
        ]
        
        # IP leak detection patterns
        self.ip_leak_patterns = [
            r'real.*ip.*detected',
            r'original.*ip.*found',
            r'ip.*leak.*detected',
            r'dns.*leak',
            r'webrtc.*leak',
        ]
        
        # Proxy service indicators
        self.proxy_service_domains = [
            'proxy-seller.com',
            'smartproxy.com',
            'oxylabs.io',
            'bright-data.com',
            'storm-proxies.com',
            'proxy-cheap.com',
            'myprivateproxy.net',
            'blazingseollc.com',
        ]
        
        # Detection rules
        self._detection_rules = [
            DetectionRule(
                id="proxy_detected",
                name="Proxy Usage Detected",
                pattern=r"(proxy.*detected|using.*proxy|proxy.*blocked)",
                description="Target service has detected proxy usage",
                category=IssueCategory.PROXY_DETECTION,
                severity=SeverityLevel.HIGH,
                confidence=DetectionConfidence.HIGH
            ),
            DetectionRule(
                id="ip_leak_detected",
                name="IP Address Leak",
                pattern=r"(real.*ip.*detected|ip.*leak|dns.*leak)",
                description="Real IP address has been leaked despite proxy usage",
                category=IssueCategory.IP_EXPOSURE,
                severity=SeverityLevel.CRITICAL,
                confidence=DetectionConfidence.HIGH
            ),
            DetectionRule(
                id="proxy_headers_exposed",
                name="Proxy Headers Exposed",
                pattern=r"(X-Forwarded-For|X-Real-IP|Via|Proxy-Authorization)",
                description="Proxy-revealing headers detected in requests",
                category=IssueCategory.PROXY_DETECTION,
                severity=SeverityLevel.MEDIUM,
                confidence=DetectionConfidence.MEDIUM
            ),
            DetectionRule(
                id="datacenter_ip_detected",
                name="Datacenter IP Detected",
                pattern=r"(datacenter.*ip|hosting.*provider|commercial.*proxy)",
                description="IP address identified as belonging to datacenter/hosting provider",
                category=IssueCategory.PROXY_DETECTION,
                severity=SeverityLevel.MEDIUM,
                confidence=DetectionConfidence.MEDIUM
            ),
            DetectionRule(
                id="webrtc_leak",
                name="WebRTC IP Leak",
                pattern=r"(webrtc.*leak|stun.*server|ice.*candidate)",
                description="WebRTC exposing real IP addresses",
                category=IssueCategory.WEBRTC_LEAK,
                severity=SeverityLevel.HIGH,
                confidence=DetectionConfidence.HIGH
            )
        ]
    
    @property
    def name(self) -> str:
        """Get detector name."""
        return "Proxy Detection Detector"
    
    @property
    def version(self) -> str:
        """Get detector version."""
        return "2.0.0"
    
    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects proxy usage detection, IP leaks, and proxy configuration issues"
    
    @property
    def categories(self) -> List[IssueCategory]:
        """Get issue categories this detector can identify."""
        return [
            IssueCategory.PROXY_DETECTION,
            IssueCategory.IP_EXPOSURE,
            IssueCategory.WEBRTC_LEAK,
            IssueCategory.DNS_LEAK
        ]
    
    @property
    def detection_rules(self) -> List[DetectionRule]:
        """Get detection rules used by this detector."""
        return self._detection_rules
    
    async def detect(self, context: DetectionContext) -> DetectionResult:
        """
        Perform proxy detection on the provided context.
        
        Args:
            context: Detection context with traces and configuration
            
        Returns:
            DetectionResult with found proxy issues and statistics
        """
        start_time = time.time()
        await self._emit_progress("proxy_detection_started", {"traces": len(context.network_traces)})
        
        # Initialize results
        issues = []
        statistics = self._init_statistics()
        errors = []
        rules_applied = []
        
        try:
            # Analyze each network trace for proxy issues
            for trace_idx, trace in enumerate(context.network_traces):
                statistics['traces_analyzed'] += 1
                
                try:
                    trace_issues = await self._analyze_trace_proxy(trace, context)
                    issues.extend(trace_issues)
                    
                    # Track rules applied
                    for issue in trace_issues:
                        rule_id = issue.metadata.get('rule_id')
                        if rule_id and rule_id not in [r.id for r in rules_applied]:
                            rule = next((r for r in self._detection_rules if r.id == rule_id), None)
                            if rule:
                                rules_applied.append(rule)
                    
                    # Emit progress every 100 traces
                    if (trace_idx + 1) % 100 == 0:
                        self._emit_progress("proxy_traces_processed", {
                            "processed": trace_idx + 1,
                            "total": len(context.network_traces),
                            "issues_found": len(issues)
                        })
                
                except Exception as e:
                    errors.append({
                        "trace_index": trace_idx,
                        "trace_id": getattr(trace, 'id', 'unknown'),
                        "error": str(e)
                    })
            
            # Perform cross-trace analysis
            cross_trace_issues = await self._analyze_cross_trace_patterns(
                context.network_traces, context
            )
            issues.extend(cross_trace_issues)
            
            # Filter issues by confidence threshold
            high_confidence_issues = [
                i for i in issues 
                if i.confidence >= context.confidence_threshold
            ]
            
            # Finalize statistics
            self._finalize_statistics(statistics, high_confidence_issues, start_time)
            statistics['detection_rules_triggered'] = len(rules_applied)
            
            result = DetectionResult(
                detector_name=self.name,
                detector_version=self.version,
                execution_time_ms=statistics['processing_time_ms'],
                issues_found=high_confidence_issues,
                detection_rules_applied=rules_applied,
                statistics=statistics,
                errors=errors
            )
            
            await self._emit_progress("proxy_detection_completed", {
                "issues_found": len(high_confidence_issues),
                "processing_time_ms": statistics['processing_time_ms']
            })
            
            return result
            
        except Exception as e:
            await self._emit_progress("proxy_detection_failed", {"error": str(e)})
            raise RuntimeError(f"Proxy detection failed: {e}")
    
    async def _analyze_trace_proxy(
        self, 
        trace: NetworkTrace, 
        context: DetectionContext
    ) -> List[Issue]:
        """
        Analyze a single network trace for proxy issues.
        
        Args:
            trace: Network trace to analyze
            context: Detection context
            
        Returns:
            List of proxy-related issues found
        """
        issues = []
        
        # Get request and response data from protocol-specific data or legacy fields
        request = self._get_request_data(trace)
        response = self._get_response_data(trace)
        
        # Check request headers for proxy indicators
        proxy_header_issues = self._check_proxy_headers(trace)
        issues.extend(proxy_header_issues)
        
        # Check response content for proxy detection messages
        detection_issues = self._check_proxy_detection_messages(trace)
        issues.extend(detection_issues)
        
        # Check for IP leak indicators
        ip_leak_issues = self._check_ip_leaks(trace)
        issues.extend(ip_leak_issues)
        
        # Check for WebRTC leaks
        webrtc_issues = self._check_webrtc_leaks(trace)
        issues.extend(webrtc_issues)
        
        # Check for datacenter IP detection
        datacenter_issues = self._check_datacenter_detection(trace)
        issues.extend(datacenter_issues)
        
        return issues
    
    async def _analyze_cross_trace_patterns(
        self, 
        traces: List[NetworkTrace], 
        context: DetectionContext
    ) -> List[Issue]:
        """
        Analyze patterns across multiple traces.
        
        Args:
            traces: List of network traces
            context: Detection context
            
        Returns:
            List of cross-trace proxy issues
        """
        issues = []
        
        # Check for consistent proxy detection across multiple requests
        detection_count = 0
        total_service_requests = 0
        
        for trace in traces:
            request_url = self._get_request_url(trace)
            if request_url and self._is_service_domain(self._extract_domain(request_url), context.service_domains):
                total_service_requests += 1
                if self._has_proxy_detection_indicators(trace):
                    detection_count += 1
        
        # If proxy detection is consistent across service requests, it's a serious issue
        if total_service_requests > 0:
            detection_rate = detection_count / total_service_requests
            if detection_rate > 0.5:  # More than 50% of service requests show proxy detection
                issues.append(self._create_consistent_proxy_detection_issue(
                    traces, detection_rate, detection_count, total_service_requests
                ))
        
        # Check for IP consistency issues
        ip_consistency_issues = self._check_ip_consistency(traces, context)
        issues.extend(ip_consistency_issues)
        
        return issues
    
    def _check_proxy_headers(self, trace: NetworkTrace) -> List[Issue]:
        """Check for proxy-revealing headers."""
        issues = []
        
        # Use the new protocol-aware method
        request = self._get_request_data(trace)
        if not request or not request.headers:
            return issues
        
        # Common proxy-revealing headers
        proxy_header_names = [
            'x-forwarded-for',
            'x-real-ip',
            'via',
            'proxy-authorization',
            'x-forwarded-proto',
            'x-forwarded-host',
            'x-proxy-authorization'
        ]
        
        proxy_headers_found = []
        for header in request.headers:
            header_name = header.get('name', '').lower()
            if header_name in proxy_header_names:
                proxy_headers_found.append(header)
        
        if proxy_headers_found:
            issues.append(self._create_proxy_headers_issue(trace, proxy_headers_found))
        
        return issues
    
    def _check_proxy_detection_messages(self, trace: NetworkTrace) -> List[Issue]:
        """Check response content for proxy detection messages."""
        issues = []
        
        # Use the new protocol-aware method
        response_body = self._get_response_body(trace)
        if not response_body:
            return issues
        
        response_body_lower = response_body.lower()
        
        for pattern in self.proxy_detection_patterns:
            if re.search(pattern, response_body_lower, re.IGNORECASE):
                issues.append(self._create_proxy_detection_issue(trace, pattern))
                break  # Only create one issue per trace to avoid duplicates
        
        return issues
    
    def _check_ip_leaks(self, trace: NetworkTrace) -> List[Issue]:
        """Check for IP leak indicators."""
        issues = []
        
        # Check response body for IP leak messages
        response_body = self._get_response_body(trace)
        if response_body:
            response_body_lower = response_body.lower()
            
            for pattern in self.ip_leak_patterns:
                if re.search(pattern, response_body_lower, re.IGNORECASE):
                    issues.append(self._create_ip_leak_issue(trace, pattern))
                    break
        
        # Check if request is to IP detection service
        request_url = self._get_request_url(trace)
        if request_url and self._is_ip_detection_service(self._extract_domain(request_url)):
            # If response contains actual IP, it might be a leak
            if response_body:
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                if re.search(ip_pattern, response_body):
                    issues.append(self._create_ip_service_leak_issue(trace))
        
        return issues
    
    def _check_webrtc_leaks(self, trace: NetworkTrace) -> List[Issue]:
        """Check for WebRTC-related IP leaks."""
        issues = []
        
        request_url = self._get_request_url(trace)
        if not request_url:
            return issues
        
        url = request_url.lower()
        
        # Check for WebRTC-related requests
        webrtc_indicators = ['stun:', 'turn:', 'ice-candidate', 'webrtc']
        
        if any(indicator in url for indicator in webrtc_indicators):
            issues.append(self._create_webrtc_leak_issue(trace))
        
        # Check response body for WebRTC leak indicators
        response_body = self._get_response_body(trace)
        if response_body:
            response_body_lower = response_body.lower()
            if re.search(r'webrtc.*leak|stun.*server|ice.*candidate', response_body_lower):
                issues.append(self._create_webrtc_leak_issue(trace))
        
        return issues
    
    def _check_datacenter_detection(self, trace: NetworkTrace) -> List[Issue]:
        """Check for datacenter IP detection."""
        issues = []
        
        response_body = self._get_response_body(trace)
        if not response_body:
            return issues
        
        response_body_lower = response_body.lower()
        
        datacenter_patterns = [
            r'datacenter.*ip',
            r'hosting.*provider',
            r'commercial.*proxy',
            r'vps.*detected',
            r'cloud.*provider'
        ]
        
        for pattern in datacenter_patterns:
            if re.search(pattern, response_body_lower, re.IGNORECASE):
                issues.append(self._create_datacenter_detection_issue(trace, pattern))
                break
        
        return issues
    
    def _has_proxy_detection_indicators(self, trace: NetworkTrace) -> bool:
        """Check if trace has proxy detection indicators."""
        response_body = self._get_response_body(trace)
        if response_body:
            response_body_lower = response_body.lower()
            return any(
                re.search(pattern, response_body_lower, re.IGNORECASE) 
                for pattern in self.proxy_detection_patterns
            )
        return False
    
    def _check_ip_consistency(
        self, 
        traces: List[NetworkTrace], 
        context: DetectionContext
    ) -> List[Issue]:
        """Check for IP consistency issues across traces."""
        issues = []
        
        # Extract IPs from IP detection service responses
        detected_ips = []
        
        for trace in traces:
            request_url = self._get_request_url(trace)
            response_body = self._get_response_body(trace)
            
            if (request_url and 
                self._is_ip_detection_service(self._extract_domain(request_url)) and
                response_body):
                
                # Extract IP addresses from response
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ips = re.findall(ip_pattern, response_body)
                detected_ips.extend(ips)
        
        # Check for multiple different IPs (might indicate IP rotation or leaks)
        unique_ips = list(set(detected_ips))
        if len(unique_ips) > 1:
            issues.append(self._create_ip_inconsistency_issue(traces, unique_ips))
        
        return issues
    
    def _create_proxy_headers_issue(
        self, 
        trace: NetworkTrace, 
        proxy_headers: List[Dict[str, str]]
    ) -> Issue:
        """Create issue for proxy-revealing headers."""
        evidence = []
        for header in proxy_headers:
            evidence.append(self._create_evidence(
                "proxy_header",
                f"Proxy header detected: {header.get('name')}",
                f"{header.get('name')}: {header.get('value')}",
                metadata={"trace_id": trace.trace_id}
            ))
        
        return self._create_issue(
            title="Proxy Headers Exposed",
            description=f"Request contains {len(proxy_headers)} proxy-revealing headers that may expose proxy usage.",
            category=IssueCategory.PROXY_DETECTION,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "proxy_headers_exposed",
                "trace_id": trace.trace_id,
                "header_count": len(proxy_headers)
            },
            remediation_suggestions=[
                "Remove or modify proxy-revealing headers",
                "Configure proxy to strip forwarding headers",
                "Use header manipulation tools"
            ]
        )
    
    def _create_proxy_detection_issue(self, trace: NetworkTrace, pattern: str) -> Issue:
        """Create issue for proxy detection."""
        evidence = [
            self._create_evidence(
                "proxy_detection_message",
                "Proxy detection message found in response",
                f"Pattern matched: {pattern}",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Proxy Usage Detected by Target Service",
            description=f"Target service has detected proxy usage. Detection pattern: {pattern}",
            category=IssueCategory.PROXY_DETECTION,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "proxy_detected",
                "trace_id": trace.trace_id,
                "detection_pattern": pattern
            },
            remediation_suggestions=[
                "Switch to residential proxy IPs",
                "Use different proxy provider",
                "Implement IP rotation",
                "Add request randomization"
            ]
        )
    
    def _create_ip_leak_issue(self, trace: NetworkTrace, pattern: str) -> Issue:
        """Create issue for IP leak."""
        evidence = [
            self._create_evidence(
                "ip_leak_indicator",
                "IP leak indicator found",
                f"Pattern matched: {pattern}",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="IP Address Leak Detected",
            description=f"Real IP address may have been leaked despite proxy usage. Pattern: {pattern}",
            category=IssueCategory.IP_EXPOSURE,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "ip_leak_detected",
                "trace_id": trace.trace_id,
                "leak_pattern": pattern
            },
            remediation_suggestions=[
                "Check DNS leak protection",
                "Verify proxy configuration",
                "Test for WebRTC leaks",
                "Use VPN with kill switch"
            ]
        )
    
    def _create_ip_service_leak_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for IP detection service leak."""
        request_url = self._get_request_url(trace)
        service_domain = self._extract_domain(request_url) if request_url else "unknown"
        
        evidence = [
            self._create_evidence(
                "ip_service_response",
                "IP detection service returned IP address",
                f"Service: {service_domain}",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="IP Detection Service Leak",
            description="IP detection service successfully returned IP address, indicating potential proxy bypass.",
            category=IssueCategory.IP_EXPOSURE,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "ip_leak_detected",
                "trace_id": trace.trace_id,
                "service": service_domain
            },
            remediation_suggestions=[
                "Block IP detection services",
                "Verify proxy is working correctly",
                "Check for DNS leaks"
            ]
        )
    
    def _create_webrtc_leak_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for WebRTC leak."""
        request_url = self._get_request_url(trace)
        
        evidence = [
            self._create_evidence(
                "webrtc_indicator",
                "WebRTC leak indicator detected",
                f"URL: {request_url or 'unknown'}",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="WebRTC IP Leak Risk",
            description="WebRTC traffic detected that may expose real IP addresses bypassing proxy.",
            category=IssueCategory.WEBRTC_LEAK,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "webrtc_leak",
                "trace_id": trace.trace_id
            },
            remediation_suggestions=[
                "Disable WebRTC in browser",
                "Use WebRTC leak protection",
                "Block STUN/TURN servers",
                "Use browser extensions to prevent WebRTC leaks"
            ]
        )
    
    def _create_datacenter_detection_issue(self, trace: NetworkTrace, pattern: str) -> Issue:
        """Create issue for datacenter IP detection."""
        evidence = [
            self._create_evidence(
                "datacenter_detection",
                "Datacenter IP detection message",
                f"Pattern: {pattern}",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Datacenter IP Detected",
            description=f"IP address identified as datacenter/hosting provider IP. Pattern: {pattern}",
            category=IssueCategory.PROXY_DETECTION,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "datacenter_ip_detected",
                "trace_id": trace.trace_id,
                "detection_pattern": pattern
            },
            remediation_suggestions=[
                "Switch to residential proxy IPs",
                "Use mobile proxy networks",
                "Avoid datacenter proxy providers"
            ]
        )
    
    def _create_consistent_proxy_detection_issue(
        self, 
        traces: List[NetworkTrace], 
        detection_rate: float,
        detection_count: int,
        total_requests: int
    ) -> Issue:
        """Create issue for consistent proxy detection."""
        evidence = [
            self._create_evidence(
                "detection_rate",
                "Proxy detection rate across service requests",
                f"{detection_rate:.2%} ({detection_count}/{total_requests})",
                metadata={"analyzed_traces": len(traces)}
            )
        ]
        
        return self._create_issue(
            title="Consistent Proxy Detection Across Requests",
            description=f"Proxy usage detected in {detection_rate:.1%} of service requests "
                       f"({detection_count} out of {total_requests}), indicating systematic detection.",
            category=IssueCategory.PROXY_DETECTION,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "proxy_detected",
                "detection_rate": detection_rate,
                "detection_count": detection_count,
                "total_requests": total_requests
            },
            remediation_suggestions=[
                "Change proxy provider immediately",
                "Use different IP ranges",
                "Implement advanced proxy rotation",
                "Consider residential proxy networks"
            ]
        )
    
    def _create_ip_inconsistency_issue(
        self, 
        traces: List[NetworkTrace], 
        unique_ips: List[str]
    ) -> Issue:
        """Create issue for IP inconsistency."""
        evidence = [
            self._create_evidence(
                "ip_addresses",
                "Multiple IP addresses detected",
                ", ".join(unique_ips),
                metadata={"ip_count": len(unique_ips)}
            )
        ]
        
        return self._create_issue(
            title="Multiple IP Addresses Detected",
            description=f"Detected {len(unique_ips)} different IP addresses, which may indicate "
                       f"IP rotation, leaks, or inconsistent proxy configuration.",
            category=IssueCategory.IP_EXPOSURE,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "ip_leak_detected",
                "unique_ips": unique_ips,
                "ip_count": len(unique_ips)
            },
            remediation_suggestions=[
                "Verify proxy configuration consistency",
                "Check for IP rotation policies",
                "Investigate potential IP leaks"
            ]
        )
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ""
    
    def _is_service_domain(self, domain: str, service_domains: List[str]) -> bool:
        """Check if domain is a service domain."""
        if not domain or not service_domains:
            return False
        
        for service_domain in service_domains:
            if domain == service_domain.lower() or domain.endswith(f".{service_domain.lower()}"):
                return True
        return False
    
    def _is_ip_detection_service(self, domain: str) -> bool:
        """Check if domain is an IP detection service."""
        ip_detection_services = [
            'whatismyipaddress.com',
            'ipinfo.io',
            'httpbin.org',
            'icanhazip.com',
            'ifconfig.me',
            'ipecho.net',
            'checkip.amazonaws.com',
            'api.ipify.org',
            'myexternalip.com',
            'ip.me'
        ]
        
        return any(service in domain.lower() for service in ip_detection_services)
