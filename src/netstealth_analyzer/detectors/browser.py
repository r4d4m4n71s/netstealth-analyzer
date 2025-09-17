"""
Browser configuration and fingerprinting detector.

This module detects browser-related stealth issues including automation detection,
fingerprinting risks, and browser configuration problems with full async support.
"""

import time
from typing import Any, AsyncIterator, Dict, List, Optional, Set
from datetime import datetime, timezone
import re
import json

from .base import BaseDetector, DetectionContext, DetectionResult
from ..models.issues import Issue, IssueEvidence, DetectionRule
from ..models.enums import SeverityLevel, IssueCategory, DetectionConfidence
from ..models.network import NetworkTrace


class BrowserDetector(BaseDetector):
    """
    Detector for browser configuration and fingerprinting issues.
    
    Analyzes network traces for browser automation detection, fingerprinting risks,
    unusual browser configurations, and other browser-related stealth issues.
    """
    
    def __init__(self, event_bus=None, confidence_threshold=0.7):
        """Initialize Browser detector."""
        super().__init__(event_bus, confidence_threshold)
        
        # Browser automation detection patterns
        self.automation_patterns = [
            # Direct automation detection
            r'automation.*detected',
            r'bot.*detected',
            r'selenium.*detected',
            r'webdriver.*detected',
            r'puppeteer.*detected',
            r'playwright.*detected',
            # Headless browser detection
            r'headless.*browser',
            r'headless.*chrome',
            r'phantom.*js',
            # Anti-bot services
            r'cloudflare.*challenge',
            r'captcha.*required',
            r'please.*verify.*human',
            r'access.*denied.*bot',
        ]
        
        # Browser fingerprinting indicators
        self.fingerprinting_patterns = [
            r'canvas.*fingerprint',
            r'webgl.*fingerprint',
            r'audio.*fingerprint',
            r'font.*fingerprint',
            r'screen.*resolution',
            r'timezone.*detection',
            r'language.*detection',
            r'plugin.*enumeration',
        ]
        
        # Suspicious user agents (automation tools)
        self.suspicious_user_agents = [
            'selenium',
            'webdriver',
            'puppeteer',
            'playwright',
            'phantomjs',
            'headlesschrome',
            'chromedriver',
            'geckodriver',
            'automation',
        ]
        
        # Common automation headers
        self.automation_headers = [
            'webdriver',
            'selenium-remote-control',
            'x-requested-with',
            'x-automation',
            'x-webdriver-remote',
        ]
        
        # Detection rules
        self._detection_rules = [
            DetectionRule(
                id="browser_automation_detected",
                name="Browser Automation Detected",
                pattern=r"(automation.*detected|bot.*detected|selenium.*detected)",
                description="Target service has detected browser automation",
                category=IssueCategory.BROWSER_CONFIG,
                severity=SeverityLevel.HIGH,
                confidence=DetectionConfidence.HIGH
            ),
            DetectionRule(
                id="headless_browser_detected",
                name="Headless Browser Detected",
                pattern=r"(headless.*browser|headless.*chrome|phantom.*js)",
                description="Headless browser usage has been detected",
                category=IssueCategory.BROWSER_CONFIG,
                severity=SeverityLevel.HIGH,
                confidence=DetectionConfidence.HIGH
            ),
            DetectionRule(
                id="browser_fingerprinting",
                name="Browser Fingerprinting Detected",
                pattern=r"(canvas.*fingerprint|webgl.*fingerprint|audio.*fingerprint)",
                description="Browser fingerprinting techniques detected",
                category=IssueCategory.JAVASCRIPT_FINGERPRINT,
                severity=SeverityLevel.MEDIUM,
                confidence=DetectionConfidence.MEDIUM
            ),
            DetectionRule(
                id="suspicious_user_agent",
                name="Suspicious User Agent",
                pattern=r"(selenium|webdriver|puppeteer|playwright|phantomjs)",
                description="User agent indicates automation tool usage",
                category=IssueCategory.BROWSER_CONFIG,
                severity=SeverityLevel.MEDIUM,
                confidence=DetectionConfidence.HIGH
            ),
            DetectionRule(
                id="anti_bot_challenge",
                name="Anti-Bot Challenge Triggered",
                pattern=r"(cloudflare.*challenge|captcha.*required|please.*verify.*human)",
                description="Anti-bot protection has been triggered",
                category=IssueCategory.BROWSER_CONFIG,
                severity=SeverityLevel.HIGH,
                confidence=DetectionConfidence.HIGH
            )
        ]
    
    @property
    def name(self) -> str:
        """Get detector name."""
        return "Browser Configuration Detector"
    
    @property
    def version(self) -> str:
        """Get detector version."""
        return "2.0.0"
    
    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects browser automation, fingerprinting, and configuration issues"
    
    @property
    def categories(self) -> List[IssueCategory]:
        """Get issue categories this detector can identify."""
        return [
            IssueCategory.BROWSER_CONFIG,
            IssueCategory.JAVASCRIPT_FINGERPRINT,
            IssueCategory.CANVAS_FINGERPRINT,
            IssueCategory.FONT_FINGERPRINT
        ]
    
    @property
    def detection_rules(self) -> List[DetectionRule]:
        """Get detection rules used by this detector."""
        return self._detection_rules
    
    async def detect(self, context: DetectionContext) -> DetectionResult:
        """
        Perform browser detection on the provided context.
        
        Args:
            context: Detection context with traces and configuration
            
        Returns:
            DetectionResult with found browser issues and statistics
        """
        start_time = time.time()
        self._emit_progress("browser_detection_started", {"traces": len(context.network_traces)})
        
        # Initialize results
        issues = []
        statistics = self._init_statistics()
        errors = []
        rules_applied = []
        
        try:
            # Analyze each network trace for browser issues
            for trace_idx, trace in enumerate(context.network_traces):
                statistics['traces_analyzed'] += 1
                
                try:
                    trace_issues = await self._analyze_trace_browser(trace, context)
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
                        self._emit_progress("browser_traces_processed", {
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
            
            self._emit_progress("browser_detection_completed", {
                "issues_found": len(high_confidence_issues),
                "processing_time_ms": statistics['processing_time_ms']
            })
            
            return result
            
        except Exception as e:
            self._emit_progress("browser_detection_failed", {"error": str(e)})
            raise RuntimeError(f"Browser detection failed: {e}")
    
    async def _analyze_trace_browser(
        self, 
        trace: NetworkTrace, 
        context: DetectionContext
    ) -> List[Issue]:
        """
        Analyze a single network trace for browser issues.
        
        Args:
            trace: Network trace to analyze
            context: Detection context
            
        Returns:
            List of browser-related issues found
        """
        issues = []
        
        # Check user agent for automation indicators
        if trace.request and trace.request.headers:
            user_agent_issues = self._check_user_agent(trace)
            issues.extend(user_agent_issues)
            
            # Check for automation headers
            automation_header_issues = self._check_automation_headers(trace)
            issues.extend(automation_header_issues)
        
        # Check response content for automation detection
        if trace.response and trace.response.body:
            automation_detection_issues = self._check_automation_detection(trace)
            issues.extend(automation_detection_issues)
            
            # Check for fingerprinting attempts
            fingerprinting_issues = self._check_fingerprinting_attempts(trace)
            issues.extend(fingerprinting_issues)
            
            # Check for anti-bot challenges
            antibot_issues = self._check_antibot_challenges(trace)
            issues.extend(antibot_issues)
        
        # Check JavaScript execution patterns
        js_issues = self._check_javascript_patterns(trace)
        issues.extend(js_issues)
        
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
            List of cross-trace browser issues
        """
        issues = []
        
        # Check for consistent automation detection
        automation_detection_count = 0
        total_service_requests = 0
        
        for trace in traces:
            if self._is_service_domain(self._extract_domain(trace.request.url), context.service_domains):
                total_service_requests += 1
                if self._has_automation_detection_indicators(trace):
                    automation_detection_count += 1
        
        if total_service_requests > 0:
            detection_rate = automation_detection_count / total_service_requests
            if detection_rate > 0.3:  # More than 30% show automation detection
                issues.append(self._create_consistent_automation_detection_issue(
                    traces, detection_rate, automation_detection_count, total_service_requests
                ))
        
        # Check for browser fingerprinting consistency
        fingerprinting_issues = self._check_fingerprinting_consistency(traces, context)
        issues.extend(fingerprinting_issues)
        
        # Check for unusual request patterns
        pattern_issues = self._check_unusual_request_patterns(traces, context)
        issues.extend(pattern_issues)
        
        return issues
    
    def _check_user_agent(self, trace: NetworkTrace) -> List[Issue]:
        """Check user agent for automation indicators."""
        issues = []
        
        if not trace.request or not trace.request.headers:
            return issues
        
        user_agent = self._get_header_value(trace.request.headers, 'user-agent')
        if not user_agent:
            return issues
        
        user_agent_lower = user_agent.lower()
        
        # Check for suspicious automation tools in user agent
        for suspicious_ua in self.suspicious_user_agents:
            if suspicious_ua in user_agent_lower:
                issues.append(self._create_suspicious_user_agent_issue(trace, user_agent, suspicious_ua))
                break
        
        # Check for unusual user agent patterns
        if self._is_unusual_user_agent(user_agent):
            issues.append(self._create_unusual_user_agent_issue(trace, user_agent))
        
        return issues
    
    def _check_automation_headers(self, trace: NetworkTrace) -> List[Issue]:
        """Check for automation-revealing headers."""
        issues = []
        
        if not trace.request or not trace.request.headers:
            return issues
        
        automation_headers_found = []
        for header in trace.request.headers:
            header_name = header.get('name', '').lower()
            if any(auto_header in header_name for auto_header in self.automation_headers):
                automation_headers_found.append(header)
        
        if automation_headers_found:
            issues.append(self._create_automation_headers_issue(trace, automation_headers_found))
        
        return issues
    
    def _check_automation_detection(self, trace: NetworkTrace) -> List[Issue]:
        """Check response content for automation detection messages."""
        issues = []
        
        if not trace.response or not trace.response.body:
            return issues
        
        response_body = str(trace.response.body).lower()
        
        for pattern in self.automation_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                issues.append(self._create_automation_detection_issue(trace, pattern))
                break  # Only create one issue per trace to avoid duplicates
        
        return issues
    
    def _check_fingerprinting_attempts(self, trace: NetworkTrace) -> List[Issue]:
        """Check for browser fingerprinting attempts."""
        issues = []
        
        if not trace.response or not trace.response.body:
            return issues
        
        response_body = str(trace.response.body).lower()
        
        # Check for fingerprinting JavaScript
        fingerprinting_found = []
        for pattern in self.fingerprinting_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                fingerprinting_found.append(pattern)
        
        if fingerprinting_found:
            issues.append(self._create_fingerprinting_issue(trace, fingerprinting_found))
        
        # Check for specific fingerprinting techniques
        if 'canvas' in response_body and ('fingerprint' in response_body or 'toDataURL' in response_body):
            issues.append(self._create_canvas_fingerprinting_issue(trace))
        
        if 'webgl' in response_body and ('getParameter' in response_body or 'getSupportedExtensions' in response_body):
            issues.append(self._create_webgl_fingerprinting_issue(trace))
        
        return issues
    
    def _check_antibot_challenges(self, trace: NetworkTrace) -> List[Issue]:
        """Check for anti-bot challenges."""
        issues = []
        
        if not trace.response:
            return issues
        
        # Check response status codes
        if trace.response.status_code in [403, 429, 503]:
            response_body = str(trace.response.body).lower() if trace.response.body else ""
            
            # Check for specific anti-bot services
            if any(pattern in response_body for pattern in ['cloudflare', 'captcha', 'challenge']):
                issues.append(self._create_antibot_challenge_issue(trace))
        
        return issues
    
    def _check_javascript_patterns(self, trace: NetworkTrace) -> List[Issue]:
        """Check for suspicious JavaScript execution patterns."""
        issues = []
        
        if not trace.request:
            return issues
        
        url = trace.request.url.lower()
        
        # Check for JavaScript-based detection attempts
        if any(js_pattern in url for js_pattern in ['detect.js', 'fingerprint.js', 'bot-detection.js']):
            issues.append(self._create_js_detection_issue(trace))
        
        return issues
    
    def _has_automation_detection_indicators(self, trace: NetworkTrace) -> bool:
        """Check if trace has automation detection indicators."""
        if trace.response and trace.response.body:
            response_body = str(trace.response.body).lower()
            return any(
                re.search(pattern, response_body, re.IGNORECASE) 
                for pattern in self.automation_patterns
            )
        return False
    
    def _check_fingerprinting_consistency(
        self, 
        traces: List[NetworkTrace], 
        context: DetectionContext
    ) -> List[Issue]:
        """Check for consistent fingerprinting attempts."""
        issues = []
        
        fingerprinting_traces = []
        for trace in traces:
            if (trace.response and trace.response.body and 
                any(re.search(pattern, str(trace.response.body), re.IGNORECASE) 
                    for pattern in self.fingerprinting_patterns)):
                fingerprinting_traces.append(trace)
        
        if len(fingerprinting_traces) > 3:  # Multiple fingerprinting attempts
            issues.append(self._create_multiple_fingerprinting_issue(fingerprinting_traces))
        
        return issues
    
    def _check_unusual_request_patterns(
        self, 
        traces: List[NetworkTrace], 
        context: DetectionContext
    ) -> List[Issue]:
        """Check for unusual request patterns that might indicate automation."""
        issues = []
        
        # Check for very consistent timing patterns
        request_intervals = []
        prev_timestamp = None
        
        for trace in traces:
            if trace.timestamp:
                if prev_timestamp:
                    interval = (trace.timestamp - prev_timestamp).total_seconds()
                    request_intervals.append(interval)
                prev_timestamp = trace.timestamp
        
        if len(request_intervals) > 5:
            # Check for suspiciously consistent intervals
            avg_interval = sum(request_intervals) / len(request_intervals)
            variance = sum((x - avg_interval) ** 2 for x in request_intervals) / len(request_intervals)
            
            if variance < 0.1 and avg_interval < 5:  # Very consistent and fast
                issues.append(self._create_robotic_timing_issue(traces, avg_interval, variance))
        
        return issues
    
    def _create_suspicious_user_agent_issue(
        self, 
        trace: NetworkTrace, 
        user_agent: str, 
        suspicious_term: str
    ) -> Issue:
        """Create issue for suspicious user agent."""
        evidence = [
            self._create_evidence(
                "user_agent",
                "Suspicious user agent detected",
                user_agent,
                metadata={"trace_id": trace.id, "suspicious_term": suspicious_term}
            )
        ]
        
        return self._create_issue(
            title="Suspicious User Agent Detected",
            description=f"User agent contains automation tool indicator: '{suspicious_term}'",
            category=IssueCategory.BROWSER_CONFIG,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "suspicious_user_agent",
                "trace_id": trace.id,
                "user_agent": user_agent,
                "suspicious_term": suspicious_term
            },
            remediation_suggestions=[
                "Use realistic user agent strings",
                "Rotate user agents periodically",
                "Avoid automation tool signatures in user agent"
            ]
        )
    
    def _create_unusual_user_agent_issue(self, trace: NetworkTrace, user_agent: str) -> Issue:
        """Create issue for unusual user agent."""
        evidence = [
            self._create_evidence(
                "user_agent",
                "Unusual user agent pattern",
                user_agent,
                metadata={"trace_id": trace.id}
            )
        ]
        
        return self._create_issue(
            title="Unusual User Agent Pattern",
            description="User agent has unusual characteristics that may indicate automation",
            category=IssueCategory.BROWSER_CONFIG,
            severity=SeverityLevel.LOW,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "suspicious_user_agent",
                "trace_id": trace.id,
                "user_agent": user_agent
            },
            remediation_suggestions=[
                "Use common, realistic user agent strings",
                "Match user agent with other browser characteristics"
            ]
        )
    
    def _create_automation_headers_issue(
        self, 
        trace: NetworkTrace, 
        automation_headers: List[Dict[str, str]]
    ) -> Issue:
        """Create issue for automation headers."""
        evidence = []
        for header in automation_headers:
            evidence.append(self._create_evidence(
                "automation_header",
                f"Automation header detected: {header.get('name')}",
                f"{header.get('name')}: {header.get('value')}",
                metadata={"trace_id": trace.id}
            ))
        
        return self._create_issue(
            title="Automation Headers Detected",
            description=f"Request contains {len(automation_headers)} automation-revealing headers",
            category=IssueCategory.BROWSER_CONFIG,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "browser_automation_detected",
                "trace_id": trace.id,
                "header_count": len(automation_headers)
            },
            remediation_suggestions=[
                "Remove automation-specific headers",
                "Use standard browser headers only",
                "Configure automation tools to hide signatures"
            ]
        )
    
    def _create_automation_detection_issue(self, trace: NetworkTrace, pattern: str) -> Issue:
        """Create issue for automation detection."""
        evidence = [
            self._create_evidence(
                "automation_detection_message",
                "Automation detection message found",
                f"Pattern matched: {pattern}",
                metadata={"trace_id": trace.id}
            )
        ]
        
        return self._create_issue(
            title="Browser Automation Detected by Target Service",
            description=f"Target service has detected browser automation. Pattern: {pattern}",
            category=IssueCategory.BROWSER_CONFIG,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "browser_automation_detected",
                "trace_id": trace.id,
                "detection_pattern": pattern
            },
            remediation_suggestions=[
                "Use stealth mode in automation tools",
                "Implement human-like behavior patterns",
                "Use undetected browser automation libraries",
                "Add random delays and mouse movements"
            ]
        )
    
    def _create_fingerprinting_issue(
        self, 
        trace: NetworkTrace, 
        fingerprinting_patterns: List[str]
    ) -> Issue:
        """Create issue for browser fingerprinting."""
        evidence = [
            self._create_evidence(
                "fingerprinting_patterns",
                "Browser fingerprinting patterns detected",
                ", ".join(fingerprinting_patterns),
                metadata={"trace_id": trace.id}
            )
        ]
        
        return self._create_issue(
            title="Browser Fingerprinting Detected",
            description=f"Browser fingerprinting techniques detected: {', '.join(fingerprinting_patterns)}",
            category=IssueCategory.JAVASCRIPT_FINGERPRINT,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "browser_fingerprinting",
                "trace_id": trace.id,
                "patterns": fingerprinting_patterns
            },
            remediation_suggestions=[
                "Use fingerprint spoofing extensions",
                "Randomize browser characteristics",
                "Block fingerprinting scripts",
                "Use privacy-focused browsers"
            ]
        )
    
    def _create_canvas_fingerprinting_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for canvas fingerprinting."""
        evidence = [
            self._create_evidence(
                "canvas_fingerprinting",
                "Canvas fingerprinting detected",
                "Canvas API usage for fingerprinting detected",
                metadata={"trace_id": trace.id}
            )
        ]
        
        return self._create_issue(
            title="Canvas Fingerprinting Detected",
            description="Canvas-based fingerprinting technique detected in response",
            category=IssueCategory.CANVAS_FINGERPRINT,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "browser_fingerprinting",
                "trace_id": trace.id,
                "fingerprint_type": "canvas"
            },
            remediation_suggestions=[
                "Block canvas fingerprinting with browser extensions",
                "Use canvas spoofing techniques",
                "Disable JavaScript for sensitive sites"
            ]
        )
    
    def _create_webgl_fingerprinting_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for WebGL fingerprinting."""
        evidence = [
            self._create_evidence(
                "webgl_fingerprinting",
                "WebGL fingerprinting detected",
                "WebGL API usage for fingerprinting detected",
                metadata={"trace_id": trace.id}
            )
        ]
        
        return self._create_issue(
            title="WebGL Fingerprinting Detected",
            description="WebGL-based fingerprinting technique detected in response",
            category=IssueCategory.JAVASCRIPT_FINGERPRINT,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "browser_fingerprinting",
                "trace_id": trace.id,
                "fingerprint_type": "webgl"
            },
            remediation_suggestions=[
                "Disable WebGL in browser settings",
                "Use WebGL spoofing extensions",
                "Block WebGL fingerprinting scripts"
            ]
        )
    
    def _create_antibot_challenge_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for anti-bot challenge."""
        evidence = [
            self._create_evidence(
                "antibot_response",
                "Anti-bot challenge response",
                f"Status: {trace.response.status_code}",
                metadata={"trace_id": trace.id}
            )
        ]
        
        return self._create_issue(
            title="Anti-Bot Challenge Triggered",
            description=f"Anti-bot protection triggered (HTTP {trace.response.status_code})",
            category=IssueCategory.BROWSER_CONFIG,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "anti_bot_challenge",
                "trace_id": trace.id,
                "status_code": trace.response.status_code
            },
            remediation_suggestions=[
                "Implement CAPTCHA solving",
                "Use residential IP addresses",
                "Add human-like delays",
                "Solve challenges manually"
            ]
        )
    
    def _create_js_detection_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for JavaScript-based detection."""
        evidence = [
            self._create_evidence(
                "js_detection_url",
                "JavaScript detection script URL",
                trace.request.url,
                metadata={"trace_id": trace.id}
            )
        ]
        
        return self._create_issue(
            title="JavaScript-Based Detection Script",
            description="Request to JavaScript script designed for bot detection",
            category=IssueCategory.JAVASCRIPT_FINGERPRINT,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "browser_fingerprinting",
                "trace_id": trace.id,
                "detection_url": trace.request.url
            },
            remediation_suggestions=[
                "Block detection scripts",
                "Use script blocking extensions",
                "Modify JavaScript execution environment"
            ]
        )
    
    def _create_consistent_automation_detection_issue(
        self, 
        traces: List[NetworkTrace], 
        detection_rate: float,
        detection_count: int,
        total_requests: int
    ) -> Issue:
        """Create issue for consistent automation detection."""
        evidence = [
            self._create_evidence(
                "detection_rate",
                "Automation detection rate across requests",
                f"{detection_rate:.2%} ({detection_count}/{total_requests})",
                metadata={"analyzed_traces": len(traces)}
            )
        ]
        
        return self._create_issue(
            title="Consistent Automation Detection",
            description=f"Browser automation detected in {detection_rate:.1%} of requests "
                       f"({detection_count} out of {total_requests})",
            category=IssueCategory.BROWSER_CONFIG,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "browser_automation_detected",
                "detection_rate": detection_rate,
                "detection_count": detection_count,
                "total_requests": total_requests
            },
            remediation_suggestions=[
                "Switch to undetected automation tools",
                "Implement advanced stealth techniques",
                "Use human-operated browsers",
                "Add behavioral randomization"
            ]
        )
    
    def _create_multiple_fingerprinting_issue(self, traces: List[NetworkTrace]) -> Issue:
        """Create issue for multiple fingerprinting attempts."""
        evidence = [
            self._create_evidence(
                "fingerprinting_attempts",
                "Multiple fingerprinting attempts detected",
                f"{len(traces)} traces with fingerprinting",
                metadata={"trace_count": len(traces)}
            )
        ]
        
        return self._create_issue(
            title="Multiple Browser Fingerprinting Attempts",
            description=f"Detected {len(traces)} fingerprinting attempts across session",
            category=IssueCategory.JAVASCRIPT_FINGERPRINT,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "browser_fingerprinting",
                "fingerprinting_count": len(traces)
            },
            remediation_suggestions=[
                "Use comprehensive fingerprint protection",
                "Block all fingerprinting scripts",
                "Use privacy-focused browser configurations"
            ]
        )
    
    def _create_robotic_timing_issue(
        self, 
        traces: List[NetworkTrace], 
        avg_interval: float, 
        variance: float
    ) -> Issue:
        """Create issue for robotic timing patterns."""
        evidence = [
            self._create_evidence(
                "timing_pattern",
                "Robotic timing pattern detected",
                f"Average interval: {avg_interval:.2f}s, Variance: {variance:.4f}",
                metadata={"trace_count": len(traces)}
            )
        ]
        
        return self._create_issue(
            title="Robotic Request Timing Pattern",
            description=f"Requests show robotic timing pattern (avg: {avg_interval:.2f}s, variance: {variance:.4f})",
            category=IssueCategory.BROWSER_CONFIG,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "browser_automation_detected",
                "avg_interval": avg_interval,
                "variance": variance,
                "trace_count": len(traces)
            },
            remediation_suggestions=[
                "Add random delays between requests",
                "Implement human-like timing patterns",
                "Use variable request intervals"
            ]
        )
    
    def _get_header_value(self, headers: List[Dict[str, str]], header_name: str) -> Optional[str]:
        """Get header value by name (case-insensitive)."""
        for header in headers:
            if header.get('name', '').lower() == header_name.lower():
                return header.get('value')
        return None
    
    def _is_unusual_user_agent(self, user_agent: str) -> bool:
        """Check if user agent has unusual characteristics."""
        # Very short user agents
        if len(user_agent) < 20:
            return True
        
        # Missing common browser indicators
        common_indicators = ['mozilla', 'webkit', 'chrome', 'firefox', 'safari', 'edge']
        if not any(indicator in user_agent.lower() for indicator in common_indicators):
            return True
        
        # Unusual version patterns
        if re.search(r'version/0\.0|chrome/0\.0|firefox/0\.0', user_agent.lower()):
            return True
        
        return False
    
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
