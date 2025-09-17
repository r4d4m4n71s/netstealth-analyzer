"""
Network anomaly and pattern detector.

This module detects network-related stealth issues including unusual traffic patterns,
timing anomalies, and network-based detection indicators with full async support.
"""

import time
from typing import Any, AsyncIterator, Dict, List, Optional, Set
from datetime import datetime, timezone
import re
from collections import defaultdict, Counter

from .base import BaseDetector, DetectionContext, DetectionResult
from ..models.issues import Issue, IssueEvidence, DetectionRule
from ..models.enums import SeverityLevel, IssueCategory, DetectionConfidence
from ..models.network import NetworkTrace


class NetworkDetector(BaseDetector):
    """
    Detector for network anomalies and patterns.
    
    Analyzes network traces for unusual traffic patterns, timing anomalies,
    suspicious network behavior, and other network-related stealth issues.
    """
    
    def __init__(self, event_bus=None, confidence_threshold=0.7):
        """Initialize Network detector."""
        super().__init__(event_bus, confidence_threshold)
        
        # Network anomaly patterns
        self.anomaly_patterns = [
            # Rate limiting indicators
            r'rate.*limit.*exceeded',
            r'too.*many.*requests',
            r'request.*throttled',
            r'slow.*down',
            # Blocking indicators
            r'access.*blocked',
            r'ip.*blocked',
            r'temporarily.*unavailable',
            r'service.*unavailable',
            # Suspicious activity detection
            r'suspicious.*activity',
            r'unusual.*traffic',
            r'automated.*behavior',
            r'bot.*traffic',
        ]
        
        # CDN and security service indicators
        self.security_service_patterns = [
            r'cloudflare',
            r'akamai',
            r'fastly',
            r'incapsula',
            r'sucuri',
            r'ddos.*protection',
            r'web.*application.*firewall',
            r'waf.*blocked',
        ]
        
        # Suspicious status codes
        self.suspicious_status_codes = {
            403: "Forbidden - Access denied",
            429: "Too Many Requests - Rate limited",
            503: "Service Unavailable - Potentially blocked",
            418: "I'm a teapot - Anti-bot response",
            444: "No Response - Nginx blocking",
            499: "Client Closed Request - Suspicious",
        }
        
        # Detection rules
        self._detection_rules = [
            DetectionRule(
                id="rate_limiting_detected",
                name="Rate Limiting Detected",
                pattern=r"(rate.*limit|too.*many.*requests|request.*throttled)",
                description="Rate limiting has been applied to requests",
                category=IssueCategory.NETWORK_ANOMALY,
                severity=SeverityLevel.HIGH,
                confidence=DetectionConfidence.HIGH
            ),
            DetectionRule(
                id="network_blocking_detected",
                name="Network Blocking Detected",
                pattern=r"(access.*blocked|ip.*blocked|service.*unavailable)",
                description="Network access has been blocked",
                category=IssueCategory.NETWORK_ANOMALY,
                severity=SeverityLevel.CRITICAL,
                confidence=DetectionConfidence.HIGH
            ),
            DetectionRule(
                id="suspicious_traffic_pattern",
                name="Suspicious Traffic Pattern",
                pattern=r"(suspicious.*activity|unusual.*traffic|automated.*behavior)",
                description="Suspicious network traffic pattern detected",
                category=IssueCategory.NETWORK_ANOMALY,
                severity=SeverityLevel.MEDIUM,
                confidence=DetectionConfidence.MEDIUM
            ),
            DetectionRule(
                id="security_service_intervention",
                name="Security Service Intervention",
                pattern=r"(cloudflare|akamai|waf.*blocked|ddos.*protection)",
                description="Security service has intervened in traffic",
                category=IssueCategory.NETWORK_ANOMALY,
                severity=SeverityLevel.HIGH,
                confidence=DetectionConfidence.MEDIUM
            ),
            DetectionRule(
                id="unusual_response_timing",
                name="Unusual Response Timing",
                pattern=r"(timeout|slow.*response|connection.*reset)",
                description="Unusual response timing patterns detected",
                category=IssueCategory.NETWORK_ANOMALY,
                severity=SeverityLevel.LOW,
                confidence=DetectionConfidence.LOW
            )
        ]
    
    @property
    def name(self) -> str:
        """Get detector name."""
        return "Network Anomaly Detector"
    
    @property
    def version(self) -> str:
        """Get detector version."""
        return "2.0.0"
    
    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects network anomalies, traffic patterns, and blocking indicators"
    
    @property
    def categories(self) -> List[IssueCategory]:
        """Get issue categories this detector can identify."""
        return [
            IssueCategory.NETWORK_ANOMALY,
            IssueCategory.CONFIGURATION
        ]
    
    @property
    def detection_rules(self) -> List[DetectionRule]:
        """Get detection rules used by this detector."""
        return self._detection_rules
    
    async def detect(self, context: DetectionContext) -> DetectionResult:
        """
        Perform network detection on the provided context.
        
        Args:
            context: Detection context with traces and configuration
            
        Returns:
            DetectionResult with found network issues and statistics
        """
        start_time = time.time()
        self._emit_progress("network_detection_started", {"traces": len(context.network_traces)})
        
        # Initialize results
        issues = []
        statistics = self._init_statistics()
        errors = []
        rules_applied = []
        
        try:
            # Analyze each network trace for network issues
            for trace_idx, trace in enumerate(context.network_traces):
                statistics['traces_analyzed'] += 1
                
                try:
                    trace_issues = await self._analyze_trace_network(trace, context)
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
                        self._emit_progress("network_traces_processed", {
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
            
            self._emit_progress("network_detection_completed", {
                "issues_found": len(high_confidence_issues),
                "processing_time_ms": statistics['processing_time_ms']
            })
            
            return result
            
        except Exception as e:
            self._emit_progress("network_detection_failed", {"error": str(e)})
            raise RuntimeError(f"Network detection failed: {e}")
    
    async def _analyze_trace_network(
        self, 
        trace: NetworkTrace, 
        context: DetectionContext
    ) -> List[Issue]:
        """
        Analyze a single network trace for network issues.
        
        Args:
            trace: Network trace to analyze
            context: Detection context
            
        Returns:
            List of network-related issues found
        """
        issues = []
        
        # Check response status codes
        if trace.response:
            status_code_issues = self._check_status_codes(trace)
            issues.extend(status_code_issues)
            
            # Check response content for network anomaly messages
            if trace.response.body:
                anomaly_issues = self._check_network_anomaly_messages(trace)
                issues.extend(anomaly_issues)
                
                # Check for security service interventions
                security_issues = self._check_security_service_interventions(trace)
                issues.extend(security_issues)
        
        # Check response timing
        timing_issues = self._check_response_timing(trace)
        issues.extend(timing_issues)
        
        # Check for unusual headers
        header_issues = self._check_unusual_headers(trace)
        issues.extend(header_issues)
        
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
            List of cross-trace network issues
        """
        issues = []
        
        # Analyze status code patterns
        status_code_issues = self._analyze_status_code_patterns(traces, context)
        issues.extend(status_code_issues)
        
        # Analyze timing patterns
        timing_pattern_issues = self._analyze_timing_patterns(traces, context)
        issues.extend(timing_pattern_issues)
        
        # Analyze request frequency patterns
        frequency_issues = self._analyze_request_frequency(traces, context)
        issues.extend(frequency_issues)
        
        # Analyze geographic patterns
        geographic_issues = self._analyze_geographic_patterns(traces, context)
        issues.extend(geographic_issues)
        
        return issues
    
    def _check_status_codes(self, trace: NetworkTrace) -> List[Issue]:
        """Check for suspicious status codes."""
        issues = []
        
        if not trace.response:
            return issues
        
        status_code = trace.response.status_code
        
        if status_code in self.suspicious_status_codes:
            issues.append(self._create_suspicious_status_code_issue(trace, status_code))
        
        return issues
    
    def _check_network_anomaly_messages(self, trace: NetworkTrace) -> List[Issue]:
        """Check response content for network anomaly messages."""
        issues = []
        
        if not trace.response or not trace.response.body:
            return issues
        
        response_body = str(trace.response.body).lower()
        
        for pattern in self.anomaly_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                issues.append(self._create_network_anomaly_issue(trace, pattern))
                break  # Only create one issue per trace to avoid duplicates
        
        return issues
    
    def _check_security_service_interventions(self, trace: NetworkTrace) -> List[Issue]:
        """Check for security service interventions."""
        issues = []
        
        if not trace.response:
            return issues
        
        # Check response body
        response_body = str(trace.response.body).lower() if trace.response.body else ""
        
        for pattern in self.security_service_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                issues.append(self._create_security_service_issue(trace, pattern))
                break
        
        # Check response headers for security services
        if trace.response.headers:
            security_headers = self._find_security_service_headers(trace.response.headers)
            if security_headers:
                issues.append(self._create_security_headers_issue(trace, security_headers))
        
        return issues
    
    def _check_response_timing(self, trace: NetworkTrace) -> List[Issue]:
        """Check for unusual response timing."""
        issues = []
        
        if not hasattr(trace, 'response_time_ms') or trace.response_time_ms is None:
            return issues
        
        response_time = trace.response_time_ms
        
        # Very slow responses might indicate throttling
        if response_time > 10000:  # 10 seconds
            issues.append(self._create_slow_response_issue(trace, response_time))
        
        # Very fast responses to complex requests might indicate caching or blocking
        elif response_time < 10 and trace.request and len(trace.request.url) > 100:
            issues.append(self._create_suspiciously_fast_response_issue(trace, response_time))
        
        return issues
    
    def _check_unusual_headers(self, trace: NetworkTrace) -> List[Issue]:
        """Check for unusual response headers."""
        issues = []
        
        if not trace.response or not trace.response.headers:
            return issues
        
        # Check for rate limiting headers
        rate_limit_headers = self._find_rate_limit_headers(trace.response.headers)
        if rate_limit_headers:
            issues.append(self._create_rate_limit_headers_issue(trace, rate_limit_headers))
        
        # Check for blocking headers
        blocking_headers = self._find_blocking_headers(trace.response.headers)
        if blocking_headers:
            issues.append(self._create_blocking_headers_issue(trace, blocking_headers))
        
        return issues
    
    def _analyze_status_code_patterns(
        self, 
        traces: List[NetworkTrace], 
        context: DetectionContext
    ) -> List[Issue]:
        """Analyze status code patterns across traces."""
        issues = []
        
        # Count status codes
        status_codes = Counter()
        service_status_codes = Counter()
        
        for trace in traces:
            if trace.response:
                status_codes[trace.response.status_code] += 1
                
                # Count status codes for service domains
                if self._is_service_domain(self._extract_domain(trace.request.url), context.service_domains):
                    service_status_codes[trace.response.status_code] += 1
        
        # Check for high error rates
        total_requests = sum(status_codes.values())
        error_requests = sum(count for code, count in status_codes.items() if code >= 400)
        
        if total_requests > 0:
            error_rate = error_requests / total_requests
            if error_rate > 0.3:  # More than 30% errors
                issues.append(self._create_high_error_rate_issue(traces, error_rate, error_requests, total_requests))
        
        # Check for consistent blocking
        service_total = sum(service_status_codes.values())
        service_blocked = sum(count for code, count in service_status_codes.items() if code in [403, 429, 503])
        
        if service_total > 0:
            block_rate = service_blocked / service_total
            if block_rate > 0.5:  # More than 50% blocked
                issues.append(self._create_consistent_blocking_issue(traces, block_rate, service_blocked, service_total))
        
        return issues
    
    def _analyze_timing_patterns(
        self, 
        traces: List[NetworkTrace], 
        context: DetectionContext
    ) -> List[Issue]:
        """Analyze timing patterns across traces."""
        issues = []
        
        # Collect response times
        response_times = []
        for trace in traces:
            if hasattr(trace, 'response_time_ms') and trace.response_time_ms is not None:
                response_times.append(trace.response_time_ms)
        
        if len(response_times) < 5:
            return issues
        
        # Calculate statistics
        avg_time = sum(response_times) / len(response_times)
        max_time = max(response_times)
        min_time = min(response_times)
        
        # Check for consistently slow responses (possible throttling)
        slow_responses = [t for t in response_times if t > 5000]  # 5 seconds
        if len(slow_responses) > len(response_times) * 0.7:  # 70% slow
            issues.append(self._create_consistent_slow_responses_issue(traces, avg_time, len(slow_responses)))
        
        # Check for bimodal distribution (fast cached vs slow real responses)
        fast_responses = [t for t in response_times if t < 100]  # 100ms
        if len(fast_responses) > 0 and len(slow_responses) > 0:
            if len(fast_responses) + len(slow_responses) > len(response_times) * 0.8:
                issues.append(self._create_bimodal_timing_issue(traces, len(fast_responses), len(slow_responses)))
        
        return issues
    
    def _analyze_request_frequency(
        self, 
        traces: List[NetworkTrace], 
        context: DetectionContext
    ) -> List[Issue]:
        """Analyze request frequency patterns."""
        issues = []
        
        # Group requests by time windows
        time_windows = defaultdict(int)
        
        for trace in traces:
            if trace.timestamp:
                # Group by minute
                minute_key = trace.timestamp.replace(second=0, microsecond=0)
                time_windows[minute_key] += 1
        
        if not time_windows:
            return issues
        
        # Check for burst patterns
        request_counts = list(time_windows.values())
        avg_requests = sum(request_counts) / len(request_counts)
        max_requests = max(request_counts)
        
        # High burst activity
        if max_requests > avg_requests * 5 and max_requests > 50:
            issues.append(self._create_burst_activity_issue(traces, max_requests, avg_requests))
        
        return issues
    
    def _analyze_geographic_patterns(
        self, 
        traces: List[NetworkTrace], 
        context: DetectionContext
    ) -> List[Issue]:
        """Analyze geographic patterns in requests."""
        issues = []
        
        # This would require IP geolocation data
        # For now, we'll check for obvious geographic indicators in URLs or responses
        
        geographic_indicators = []
        for trace in traces:
            if trace.request:
                url = trace.request.url.lower()
                # Check for geographic TLDs or subdomains
                if any(geo in url for geo in ['.co.uk', '.de', '.fr', '.jp', '.au', 'us.', 'eu.', 'asia.']):
                    geographic_indicators.append(trace)
        
        # If we have geographic indicators but they're inconsistent with expected geography
        if len(geographic_indicators) > 3 and context.expected_geography:
            issues.append(self._create_geographic_inconsistency_issue(geographic_indicators, context.expected_geography))
        
        return issues
    
    def _create_suspicious_status_code_issue(self, trace: NetworkTrace, status_code: int) -> Issue:
        """Create issue for suspicious status code."""
        evidence = [
            self._create_evidence(
                "status_code",
                f"Suspicious HTTP status code: {status_code}",
                f"HTTP {status_code}: {self.suspicious_status_codes[status_code]}",
                metadata={"trace_id": trace.id}
            )
        ]
        
        # Determine rule ID based on status code
        if status_code in [403, 444]:
            rule_id = "network_blocking_detected"
            severity = SeverityLevel.CRITICAL
        elif status_code == 429:
            rule_id = "rate_limiting_detected"
            severity = SeverityLevel.HIGH
        else:
            rule_id = "suspicious_traffic_pattern"
            severity = SeverityLevel.MEDIUM
        
        return self._create_issue(
            title=f"Suspicious HTTP Status Code: {status_code}",
            description=f"Received suspicious HTTP status code {status_code}: {self.suspicious_status_codes[status_code]}",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=severity,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": rule_id,
                "trace_id": trace.id,
                "status_code": status_code
            },
            remediation_suggestions=[
                "Check if IP is blocked or rate limited",
                "Implement request throttling",
                "Use different IP addresses",
                "Add delays between requests"
            ]
        )
    
    def _create_network_anomaly_issue(self, trace: NetworkTrace, pattern: str) -> Issue:
        """Create issue for network anomaly message."""
        evidence = [
            self._create_evidence(
                "anomaly_message",
                "Network anomaly message detected",
                f"Pattern matched: {pattern}",
                metadata={"trace_id": trace.id}
            )
        ]
        
        return self._create_issue(
            title="Network Anomaly Detected",
            description=f"Network anomaly detected in response. Pattern: {pattern}",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "suspicious_traffic_pattern",
                "trace_id": trace.id,
                "anomaly_pattern": pattern
            },
            remediation_suggestions=[
                "Reduce request frequency",
                "Implement human-like behavior",
                "Use different IP addresses",
                "Add random delays"
            ]
        )
    
    def _create_security_service_issue(self, trace: NetworkTrace, pattern: str) -> Issue:
        """Create issue for security service intervention."""
        evidence = [
            self._create_evidence(
                "security_service",
                "Security service intervention detected",
                f"Service pattern: {pattern}",
                metadata={"trace_id": trace.id}
            )
        ]
        
        return self._create_issue(
            title="Security Service Intervention",
            description=f"Security service intervention detected: {pattern}",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "security_service_intervention",
                "trace_id": trace.id,
                "service_pattern": pattern
            },
            remediation_suggestions=[
                "Use residential IP addresses",
                "Implement advanced evasion techniques",
                "Reduce request frequency",
                "Use different user agents"
            ]
        )
    
    def _create_security_headers_issue(
        self, 
        trace: NetworkTrace, 
        security_headers: List[Dict[str, str]]
    ) -> Issue:
        """Create issue for security service headers."""
        evidence = []
        for header in security_headers:
            evidence.append(self._create_evidence(
                "security_header",
                f"Security service header: {header.get('name')}",
                f"{header.get('name')}: {header.get('value')}",
                metadata={"trace_id": trace.id}
            ))
        
        return self._create_issue(
            title="Security Service Headers Detected",
            description=f"Detected {len(security_headers)} security service headers in response",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "security_service_intervention",
                "trace_id": trace.id,
                "header_count": len(security_headers)
            },
            remediation_suggestions=[
                "Monitor for additional security measures",
                "Adjust request patterns",
                "Use different IP ranges"
            ]
        )
    
    def _create_slow_response_issue(self, trace: NetworkTrace, response_time: float) -> Issue:
        """Create issue for slow response."""
        evidence = [
            self._create_evidence(
                "response_time",
                "Unusually slow response time",
                f"{response_time:.0f}ms",
                metadata={"trace_id": trace.id}
            )
        ]
        
        return self._create_issue(
            title="Unusually Slow Response",
            description=f"Response took {response_time:.0f}ms, which may indicate throttling or blocking",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.LOW,
            confidence=DetectionConfidence.LOW,
            evidence=evidence,
            metadata={
                "rule_id": "unusual_response_timing",
                "trace_id": trace.id,
                "response_time_ms": response_time
            },
            remediation_suggestions=[
                "Check for rate limiting",
                "Reduce request frequency",
                "Monitor for consistent slow responses"
            ]
        )
    
    def _create_suspiciously_fast_response_issue(self, trace: NetworkTrace, response_time: float) -> Issue:
        """Create issue for suspiciously fast response."""
        evidence = [
            self._create_evidence(
                "response_time",
                "Suspiciously fast response time",
                f"{response_time:.0f}ms",
                metadata={"trace_id": trace.id}
            )
        ]
        
        return self._create_issue(
            title="Suspiciously Fast Response",
            description=f"Response was unusually fast ({response_time:.0f}ms) for complex request, may indicate caching or blocking",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.LOW,
            confidence=DetectionConfidence.LOW,
            evidence=evidence,
            metadata={
                "rule_id": "unusual_response_timing",
                "trace_id": trace.id,
                "response_time_ms": response_time
            },
            remediation_suggestions=[
                "Verify response content is correct",
                "Check for cached responses",
                "Monitor for consistent fast responses"
            ]
        )
    
    def _create_rate_limit_headers_issue(
        self, 
        trace: NetworkTrace, 
        rate_limit_headers: List[Dict[str, str]]
    ) -> Issue:
        """Create issue for rate limiting headers."""
        evidence = []
        for header in rate_limit_headers:
            evidence.append(self._create_evidence(
                "rate_limit_header",
                f"Rate limiting header: {header.get('name')}",
                f"{header.get('name')}: {header.get('value')}",
                metadata={"trace_id": trace.id}
            ))
        
        return self._create_issue(
            title="Rate Limiting Headers Detected",
            description=f"Detected {len(rate_limit_headers)} rate limiting headers in response",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "rate_limiting_detected",
                "trace_id": trace.id,
                "header_count": len(rate_limit_headers)
            },
            remediation_suggestions=[
                "Respect rate limits",
                "Implement exponential backoff",
                "Use multiple IP addresses",
                "Reduce request frequency"
            ]
        )
    
    def _create_blocking_headers_issue(
        self, 
        trace: NetworkTrace, 
        blocking_headers: List[Dict[str, str]]
    ) -> Issue:
        """Create issue for blocking headers."""
        evidence = []
        for header in blocking_headers:
            evidence.append(self._create_evidence(
                "blocking_header",
                f"Blocking header: {header.get('name')}",
                f"{header.get('name')}: {header.get('value')}",
                metadata={"trace_id": trace.id}
            ))
        
        return self._create_issue(
            title="Blocking Headers Detected",
            description=f"Detected {len(blocking_headers)} blocking-related headers in response",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "network_blocking_detected",
                "trace_id": trace.id,
                "header_count": len(blocking_headers)
            },
            remediation_suggestions=[
                "Change IP address immediately",
                "Use different proxy provider",
                "Implement IP rotation",
                "Reduce activity level"
            ]
        )
    
    def _create_high_error_rate_issue(
        self, 
        traces: List[NetworkTrace], 
        error_rate: float,
        error_count: int,
        total_count: int
    ) -> Issue:
        """Create issue for high error rate."""
        evidence = [
            self._create_evidence(
                "error_rate",
                "High error rate across requests",
                f"{error_rate:.2%} ({error_count}/{total_count})",
                metadata={"analyzed_traces": len(traces)}
            )
        ]
        
        return self._create_issue(
            title="High Error Rate Detected",
            description=f"High error rate detected: {error_rate:.1%} of requests failed ({error_count}/{total_count})",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "network_blocking_detected",
                "error_rate": error_rate,
                "error_count": error_count,
                "total_count": total_count
            },
            remediation_suggestions=[
                "Investigate cause of errors",
                "Reduce request frequency",
                "Check IP reputation",
                "Implement error handling"
            ]
        )
    
    def _create_consistent_blocking_issue(
        self, 
        traces: List[NetworkTrace], 
        block_rate: float,
        blocked_count: int,
        total_count: int
    ) -> Issue:
        """Create issue for consistent blocking."""
        evidence = [
            self._create_evidence(
                "blocking_rate",
                "Consistent blocking across service requests",
                f"{block_rate:.2%} ({blocked_count}/{total_count})",
                metadata={"analyzed_traces": len(traces)}
            )
        ]
        
        return self._create_issue(
            title="Consistent Blocking Detected",
            description=f"Consistent blocking detected: {block_rate:.1%} of service requests blocked ({blocked_count}/{total_count})",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "network_blocking_detected",
                "block_rate": block_rate,
                "blocked_count": blocked_count,
                "total_count": total_count
            },
            remediation_suggestions=[
                "Change IP address immediately",
                "Use different proxy provider",
                "Implement advanced IP rotation",
                "Reduce activity to minimum"
            ]
        )
    
    def _create_consistent_slow_responses_issue(
        self, 
        traces: List[NetworkTrace], 
        avg_time: float,
        slow_count: int
    ) -> Issue:
        """Create issue for consistent slow responses."""
        evidence = [
            self._create_evidence(
                "slow_responses",
                "Consistent slow response pattern",
                f"Average: {avg_time:.0f}ms, Slow responses: {slow_count}",
                metadata={"trace_count": len(traces)}
            )
        ]
        
        return self._create_issue(
            title="Consistent Slow Responses Detected",
            description=f"Detected consistent slow responses (avg: {avg_time:.0f}ms, {slow_count} slow responses)",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "unusual_response_timing",
                "avg_time": avg_time,
                "slow_count": slow_count
            },
            remediation_suggestions=[
                "Check for rate limiting",
                "Reduce request frequency",
                "Use different IP addresses"
            ]
        )
    
    def _create_bimodal_timing_issue(
        self, 
        traces: List[NetworkTrace], 
        fast_count: int,
        slow_count: int
    ) -> Issue:
        """Create issue for bimodal timing distribution."""
        evidence = [
            self._create_evidence(
                "timing_distribution",
                "Bimodal timing distribution detected",
                f"Fast responses: {fast_count}, Slow responses: {slow_count}",
                metadata={"trace_count": len(traces)}
            )
        ]
        
        return self._create_issue(
            title="Bimodal Response Timing Pattern",
            description=f"Detected bimodal timing pattern: {fast_count} fast, {slow_count} slow responses",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.LOW,
            confidence=DetectionConfidence.LOW,
            evidence=evidence,
            metadata={
                "rule_id": "unusual_response_timing",
                "fast_count": fast_count,
                "slow_count": slow_count
            },
            remediation_suggestions=[
                "Monitor for caching behavior",
                "Check for selective throttling",
                "Analyze response content differences"
            ]
        )
    
    def _create_burst_activity_issue(
        self, 
        traces: List[NetworkTrace], 
        max_requests: int,
        avg_requests: float
    ) -> Issue:
        """Create issue for burst activity."""
        evidence = [
            self._create_evidence(
                "burst_activity",
                "High burst activity detected",
                f"Max: {max_requests} requests/minute, Average: {avg_requests:.1f}",
                metadata={"trace_count": len(traces)}
            )
        ]
        
        return self._create_issue(
            title="High Burst Activity Detected",
            description=f"Detected high burst activity: {max_requests} requests/minute (avg: {avg_requests:.1f})",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "suspicious_traffic_pattern",
                "max_requests": max_requests,
                "avg_requests": avg_requests
            },
            remediation_suggestions=[
                "Implement request smoothing",
                "Add random delays",
                "Distribute requests over time"
            ]
        )
    
    def _create_geographic_inconsistency_issue(
        self, 
        traces: List[NetworkTrace], 
        expected_geography: str
    ) -> Issue:
        """Create issue for geographic inconsistency."""
        evidence = [
            self._create_evidence(
                "geographic_indicators",
                "Geographic inconsistency detected",
                f"Expected: {expected_geography}, Found indicators in {len(traces)} traces",
                metadata={"trace_count": len(traces)}
            )
        ]
        
        return self._create_issue(
            title="Geographic Inconsistency Detected",
            description=f"Geographic indicators inconsistent with expected region: {expected_geography}",
            category=IssueCategory.NETWORK_ANOMALY,
            severity=SeverityLevel.LOW,
            confidence=DetectionConfidence.LOW,
            evidence=evidence,
            metadata={
                "rule_id": "suspicious_traffic_pattern",
                "expected_geography": expected_geography,
                "indicator_count": len(traces)
            },
            remediation_suggestions=[
                "Verify proxy geographic location",
                "Use region-appropriate proxies",
                "Check DNS resolution"
            ]
        )
    
    def _find_security_service_headers(self, headers: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Find security service headers."""
        security_headers = []
        security_header_names = [
            'cf-ray', 'cf-cache-status', 'server-cloudflare',
            'x-akamai-request-id', 'x-cache-remote',
            'x-served-by', 'x-cache', 'x-fastly-request-id',
            'x-sucuri-id', 'x-sucuri-cache'
        ]
        
        for header in headers:
            header_name = header.get('name', '').lower()
            if any(sec_header in header_name for sec_header in security_header_names):
                security_headers.append(header)
        
        return security_headers
    
    def _find_rate_limit_headers(self, headers: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Find rate limiting headers."""
        rate_limit_headers = []
        rate_limit_header_names = [
            'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',
            'x-rate-limit-limit', 'x-rate-limit-remaining', 'x-rate-limit-reset',
            'retry-after', 'x-retry-after'
        ]
        
        for header in headers:
            header_name = header.get('name', '').lower()
            if header_name in rate_limit_header_names:
                rate_limit_headers.append(header)
        
        return rate_limit_headers
    
    def _find_blocking_headers(self, headers: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Find blocking-related headers."""
        blocking_headers = []
        blocking_header_names = [
            'x-blocked', 'x-access-denied', 'x-ban-reason',
            'x-firewall-blocked', 'x-security-block'
        ]
        
        for header in headers:
            header_name = header.get('name', '').lower()
            if any(block_header in header_name for block_header in blocking_header_names):
                blocking_headers.append(header)
        
        return blocking_headers
    
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
