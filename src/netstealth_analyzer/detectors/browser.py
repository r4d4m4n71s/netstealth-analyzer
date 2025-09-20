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
from ..models.network import NetworkTrace, HttpTrace


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
        await self._emit_progress("browser_detection_started", {"traces": len(context.network_traces)})
        
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
                        # Handle both dict and IssueMetadata object
                        if hasattr(issue.metadata, 'get'):
                            rule_id = issue.metadata.get('rule_id')
                        else:
                            rule_id = getattr(issue.metadata, 'rule_id', None)
                        
                        if rule_id and rule_id not in [r.id for r in rules_applied]:
                            rule = next((r for r in self._detection_rules if r.id == rule_id), None)
                            if rule:
                                rules_applied.append(rule)
                    
                    # Emit progress every 100 traces
                    if (trace_idx + 1) % 100 == 0:
                        await self._emit_progress("browser_traces_processed", {
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
            
            await self._emit_progress("browser_detection_completed", {
                "issues_found": len(high_confidence_issues),
                "processing_time_ms": statistics['processing_time_ms']
            })
            
            return result
            
        except Exception as e:
            await self._emit_progress("browser_detection_failed", {"error": str(e)})
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
        
        # Use protocol-aware methods to get HTTP data
        request = self._get_request_data(trace)
        response = self._get_response_data(trace)
        
        # Check user agent for automation indicators
        if request and request.headers:
            user_agent_issues = self._check_user_agent(trace)
            issues.extend(user_agent_issues)
            
            # Check for automation headers
            automation_header_issues = self._check_automation_headers(trace)
            issues.extend(automation_header_issues)
        
        # Check response content for automation detection
        if response and response.body:
            automation_detection_issues = self._check_automation_detection(trace)
            issues.extend(automation_detection_issues)
            
            # Check for fingerprinting attempts
            fingerprinting_issues = self._check_fingerprinting_attempts(trace)
            issues.extend(fingerprinting_issues)
            
            # Check for anti-bot challenges
            antibot_issues = self._check_antibot_challenges(trace)
            issues.extend(antibot_issues)
        
        # Check JavaScript execution patterns
        if request:
            js_issues = self._check_javascript_patterns(trace)
            issues.extend(js_issues)
        
        # Check for data exposure issues
        data_exposure_issues = self._check_data_exposure(trace)
        issues.extend(data_exposure_issues)
        
        # Check for tracking indicators
        tracking_issues = self._check_tracking_indicators(trace)
        issues.extend(tracking_issues)
        
        # Check for debug information leakage
        debug_issues = self._check_debug_leakage(trace)
        issues.extend(debug_issues)
        
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
            http_request = trace.metadata.get('http_request')
            if http_request and http_request.get('url'):
                domain = self._extract_domain(http_request['url'])
                if self._is_service_domain(domain, context.service_domains):
                    total_service_requests += 1
                    if self._has_automation_detection_indicators_from_metadata(trace):
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
        
        request = self._get_request_data(trace)
        if not request or not request.headers:
            return issues
        
        user_agent = self._get_header_value(request.headers, 'user-agent')
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
        
        request = self._get_request_data(trace)
        if not request or not request.headers:
            return issues
        
        automation_headers_found = []
        for header in request.headers:
            header_name = header.get('name', '').lower()
            if any(auto_header in header_name for auto_header in self.automation_headers):
                automation_headers_found.append(header)
        
        if automation_headers_found:
            issues.append(self._create_automation_headers_issue(trace, automation_headers_found))
        
        return issues
    
    def _check_automation_detection(self, trace: NetworkTrace) -> List[Issue]:
        """Check response content for automation detection messages."""
        issues = []
        
        response = self._get_response_data(trace)
        if not response or not response.body:
            return issues
        
        response_body = str(response.body).lower()
        
        for pattern in self.automation_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                issues.append(self._create_automation_detection_issue(trace, pattern))
                break  # Only create one issue per trace to avoid duplicates
        
        return issues
    
    def _check_fingerprinting_attempts(self, trace: NetworkTrace) -> List[Issue]:
        """Check for browser fingerprinting attempts."""
        issues = []
        
        response = self._get_response_data(trace)
        if not response or not response.body:
            return issues
        
        response_body = str(response.body).lower()
        
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
        
        if 'webgl' in response_body and ('getparameter' in response_body or 'getsupportedextensions' in response_body):
            issues.append(self._create_webgl_fingerprinting_issue(trace))
        
        return issues
    
    def _check_antibot_challenges(self, trace: NetworkTrace) -> List[Issue]:
        """Check for anti-bot challenges."""
        issues = []
        
        response = self._get_response_data(trace)
        if not response:
            return issues
        
        # Check response status codes
        if response.status_code in [403, 429, 503]:
            response_body = str(response.body).lower() if response.body else ""
            
            # Check for specific anti-bot services
            if any(pattern in response_body for pattern in ['cloudflare', 'captcha', 'challenge']):
                issues.append(self._create_antibot_challenge_issue(trace))
        
        return issues
    
    def _check_javascript_patterns(self, trace: NetworkTrace) -> List[Issue]:
        """Check for suspicious JavaScript execution patterns."""
        issues = []
        
        request = self._get_request_data(trace)
        if not request:
            return issues
        
        url = request.url.lower()
        
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
            http_response = trace.metadata.get('http_response')
            if (http_response and http_response.get('body') and 
                any(re.search(pattern, str(http_response['body']), re.IGNORECASE) 
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
            # Try to get timestamp from trace or metadata
            timestamp = trace.trace_start
            if not timestamp:
                http_request = trace.metadata.get('http_request')
                if http_request and http_request.get('timestamp'):
                    timestamp = http_request['timestamp']
            
            if timestamp:
                if prev_timestamp:
                    interval = (timestamp - prev_timestamp).total_seconds()
                    request_intervals.append(interval)
                prev_timestamp = timestamp
        
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
                metadata={"trace_id": trace.trace_id, "suspicious_term": suspicious_term}
            )
        ]
        
        return self._create_issue(
            title="Suspicious User Agent Detected",
            description=f"User agent contains automation tool indicator: '{suspicious_term}'",
            category=IssueCategory.BROWSER_AUTOMATION,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "suspicious_user_agent",
                "trace_id": trace.trace_id,
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
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Unusual User Agent Pattern",
            description="User agent has unusual characteristics that may indicate automation",
            category=IssueCategory.BROWSER_AUTOMATION,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "suspicious_user_agent",
                "trace_id": trace.trace_id,
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
                metadata={"trace_id": trace.trace_id}
            ))
        
        return self._create_issue(
            title="Automation Headers Detected",
            description=f"Request contains {len(automation_headers)} automation-revealing headers",
            category=IssueCategory.BROWSER_AUTOMATION,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "browser_automation_detected",
                "trace_id": trace.trace_id,
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
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Browser Automation Detected by Target Service",
            description=f"Target service has detected browser automation. Pattern: {pattern}",
            category=IssueCategory.BROWSER_AUTOMATION,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "browser_automation_detected",
                "trace_id": trace.trace_id,
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
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Browser Fingerprinting Detected",
            description=f"Browser fingerprinting techniques detected: {', '.join(fingerprinting_patterns)}",
            category=IssueCategory.FINGERPRINTING,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.MEDIUM,
            evidence=evidence,
            metadata={
                "rule_id": "browser_fingerprinting",
                "trace_id": trace.trace_id,
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
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Canvas Fingerprinting Detected",
            description="Canvas-based fingerprinting technique detected in response",
            category=IssueCategory.FINGERPRINTING,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "browser_fingerprinting",
                "trace_id": trace.trace_id,
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
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="WebGL Fingerprinting Detected",
            description="WebGL-based fingerprinting technique detected in response",
            category=IssueCategory.FINGERPRINTING,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "browser_fingerprinting",
                "trace_id": trace.trace_id,
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
        response = self._get_response_data(trace)
        status_code = response.status_code if response else 0
        
        evidence = [
            self._create_evidence(
                "antibot_response",
                "Anti-bot challenge response",
                f"Status: {status_code}",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Anti-Bot Challenge Triggered",
            description=f"Anti-bot protection triggered (HTTP {status_code})",
            category=IssueCategory.BROWSER_AUTOMATION,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "anti_bot_challenge",
                "trace_id": trace.trace_id,
                "status_code": status_code
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
        request = self._get_request_data(trace)
        url = request.url if request else "unknown"
        
        evidence = [
            self._create_evidence(
                "js_detection_url",
                "JavaScript detection script URL",
                url,
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        # Extract filename from URL for description
        filename = url.split('/')[-1] if '/' in url else url
        
        return self._create_issue(
            title="JavaScript-Based Detection Script",
            description=f"Request to JavaScript script designed for bot detection: {filename}",
            category=IssueCategory.FINGERPRINTING,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "browser_fingerprinting",
                "trace_id": trace.trace_id,
                "detection_url": url
            },
            remediation_suggestions=[
                "Block detection scripts",
                "Use script blocking extensions",
                "Modify JavaScript execution environment"
            ]
        )
    
    # Issue creation methods for new categories
    def _create_api_key_exposure_issue(self, trace: NetworkTrace, url: str) -> Issue:
        """Create issue for API key exposure in URL."""
        evidence = [
            self._create_evidence(
                "api_key_in_url",
                "API key exposed in URL parameters",
                url,
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="API Key Exposed in URL",
            description="Sensitive API key found in URL parameters",
            category=IssueCategory.DATA_EXPOSURE,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "api_key_exposure",
                "trace_id": trace.trace_id,
                "exposure_location": "url_parameters"
            },
            remediation_suggestions=[
                "Move API keys to request headers",
                "Use secure authentication methods",
                "Implement proper key management"
            ]
        )
    
    def _create_sensitive_param_exposure_issue(self, trace: NetworkTrace, url: str) -> Issue:
        """Create issue for sensitive parameter exposure."""
        evidence = [
            self._create_evidence(
                "sensitive_params_in_url",
                "Sensitive parameters exposed in URL",
                url,
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Sensitive Data in URL Parameters",
            description="Sensitive information (SSN, credit card, etc.) found in URL parameters",
            category=IssueCategory.DATA_EXPOSURE,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "sensitive_param_exposure",
                "trace_id": trace.trace_id,
                "exposure_location": "url_parameters"
            },
            remediation_suggestions=[
                "Use POST requests for sensitive data",
                "Encrypt sensitive parameters",
                "Implement proper data handling"
            ]
        )
    
    def _create_debug_param_exposure_issue(self, trace: NetworkTrace, url: str) -> Issue:
        """Create issue for debug parameter exposure."""
        evidence = [
            self._create_evidence(
                "debug_params_in_url",
                "Debug parameters exposed in URL",
                url,
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Debug Parameters in Production URL",
            description="Debug parameters found in URL that may expose sensitive information",
            category=IssueCategory.DEBUG_LEAKAGE,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "debug_param_exposure",
                "trace_id": trace.trace_id,
                "exposure_location": "url_parameters"
            },
            remediation_suggestions=[
                "Remove debug parameters from production",
                "Use environment-specific configurations",
                "Implement proper debug controls"
            ]
        )
    
    def _create_pii_exposure_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for PII exposure in response."""
        evidence = [
            self._create_evidence(
                "pii_in_response",
                "Personal Identifiable Information in response body",
                "PII detected in response content",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Personal Information Exposed in Response",
            description="Personal identifiable information (PII) found in response body",
            category=IssueCategory.DATA_EXPOSURE,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "pii_exposure",
                "trace_id": trace.trace_id,
                "exposure_location": "response_body"
            },
            remediation_suggestions=[
                "Implement data masking",
                "Use proper access controls",
                "Encrypt sensitive data in responses"
            ]
        )
    
    def _create_internal_data_exposure_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for internal data exposure."""
        evidence = [
            self._create_evidence(
                "internal_data_in_response",
                "Internal system data in response body",
                "Internal data detected in response content",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Internal System Data Exposed",
            description="Internal system data found in response that should not be public",
            category=IssueCategory.DATA_EXPOSURE,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "internal_data_exposure",
                "trace_id": trace.trace_id,
                "exposure_location": "response_body"
            },
            remediation_suggestions=[
                "Filter internal data from responses",
                "Implement proper data sanitization",
                "Use response filtering mechanisms"
            ]
        )
    
    def _create_tracking_request_issue(self, trace: NetworkTrace, url: str) -> Issue:
        """Create issue for tracking request."""
        evidence = [
            self._create_evidence(
                "tracking_request_url",
                "Request to tracking/analytics service",
                url,
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Third-Party Tracking Request",
            description="Request made to third-party tracking or analytics service",
            category=IssueCategory.TRACKING,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "tracking_request",
                "trace_id": trace.trace_id,
                "tracking_url": url
            },
            remediation_suggestions=[
                "Block tracking requests",
                "Use privacy-focused alternatives",
                "Implement consent management"
            ]
        )
    
    def _create_fingerprint_collection_issue(self, trace: NetworkTrace, url: str) -> Issue:
        """Create issue for fingerprint collection."""
        evidence = [
            self._create_evidence(
                "fingerprint_collection_url",
                "Request to fingerprint collection service",
                url,
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Browser Fingerprint Collection",
            description="Request made to service that collects browser fingerprints",
            category=IssueCategory.FINGERPRINTING,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "fingerprint_collection",
                "trace_id": trace.trace_id,
                "collection_url": url
            },
            remediation_suggestions=[
                "Block fingerprint collection requests",
                "Use fingerprint spoofing",
                "Implement privacy protection"
            ]
        )
    
    def _create_comprehensive_tracking_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for comprehensive tracking."""
        evidence = [
            self._create_evidence(
                "comprehensive_tracking_data",
                "Comprehensive user tracking data in request",
                "Extensive user tracking detected",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Comprehensive User Tracking",
            description="Extensive user tracking data being sent to third-party service",
            category=IssueCategory.TRACKING,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "comprehensive_tracking",
                "trace_id": trace.trace_id,
                "tracking_type": "comprehensive"
            },
            remediation_suggestions=[
                "Disable comprehensive tracking",
                "Use privacy-focused browsing",
                "Block tracking scripts"
            ]
        )
    
    def _create_behavioral_tracking_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for behavioral tracking."""
        evidence = [
            self._create_evidence(
                "behavioral_tracking_data",
                "Behavioral tracking data in request",
                "User behavior tracking detected",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Behavioral Tracking Detected",
            description="User behavioral data being tracked and transmitted",
            category=IssueCategory.TRACKING,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "behavioral_tracking",
                "trace_id": trace.trace_id,
                "tracking_type": "behavioral"
            },
            remediation_suggestions=[
                "Disable behavioral tracking",
                "Use script blockers",
                "Enable privacy mode"
            ]
        )
    
    def _create_tracking_cookies_issue(self, trace: NetworkTrace, cookies: List[str]) -> Issue:
        """Create issue for tracking cookies."""
        evidence = [
            self._create_evidence(
                "tracking_cookies",
                "Tracking cookies set by response",
                f"{len(cookies)} tracking cookies detected",
                metadata={"trace_id": trace.trace_id, "cookie_count": len(cookies)}
            )
        ]
        
        return self._create_issue(
            title="Tracking Cookies Set",
            description=f"Response sets {len(cookies)} tracking cookies for user monitoring",
            category=IssueCategory.TRACKING,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "tracking_cookies",
                "trace_id": trace.trace_id,
                "cookie_count": len(cookies)
            },
            remediation_suggestions=[
                "Block tracking cookies",
                "Use cookie management tools",
                "Enable privacy protection"
            ]
        )
    
    def _create_debug_headers_issue(self, trace: NetworkTrace, headers: List[Dict[str, str]]) -> Issue:
        """Create issue for debug headers."""
        evidence = []
        for header in headers:
            evidence.append(self._create_evidence(
                "debug_header",
                f"Debug header: {header.get('name')}",
                f"{header.get('name')}: {header.get('value')}",
                metadata={"trace_id": trace.trace_id}
            ))
        
        return self._create_issue(
            title="Debug Information in Response Headers",
            description=f"Response contains {len(headers)} debug headers exposing system information",
            category=IssueCategory.DEBUG_LEAKAGE,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "debug_headers",
                "trace_id": trace.trace_id,
                "header_count": len(headers)
            },
            remediation_suggestions=[
                "Remove debug headers from production",
                "Implement proper header filtering",
                "Use environment-specific configurations"
            ]
        )
    
    def _create_debug_mode_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for debug mode detection."""
        evidence = [
            self._create_evidence(
                "debug_mode_indicator",
                "Debug mode indicator in response",
                "Debug mode detected in response content",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Debug Mode Enabled in Production",
            description="Application appears to be running in debug mode in production environment",
            category=IssueCategory.DEBUG_LEAKAGE,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "debug_mode_enabled",
                "trace_id": trace.trace_id,
                "debug_type": "application_debug"
            },
            remediation_suggestions=[
                "Disable debug mode in production",
                "Use environment-specific configurations",
                "Implement proper deployment practices"
            ]
        )
    
    def _create_system_info_leakage_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for system information leakage."""
        evidence = [
            self._create_evidence(
                "system_info_leakage",
                "System information in response",
                "Internal system information detected",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="System Information Leakage",
            description="Response contains internal system information that should not be exposed",
            category=IssueCategory.DEBUG_LEAKAGE,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "system_info_leakage",
                "trace_id": trace.trace_id,
                "leakage_type": "system_metrics"
            },
            remediation_suggestions=[
                "Filter system information from responses",
                "Implement proper error handling",
                "Use production-safe logging"
            ]
        )
    
    def _create_admin_token_leakage_issue(self, trace: NetworkTrace) -> Issue:
        """Create issue for admin token leakage."""
        evidence = [
            self._create_evidence(
                "admin_token_leakage",
                "Admin/internal token in response",
                "Administrative token detected in response",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Administrative Token Exposed",
            description="Response contains administrative or internal tokens that should be protected",
            category=IssueCategory.DEBUG_LEAKAGE,
            severity=SeverityLevel.CRITICAL,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "admin_token_leakage",
                "trace_id": trace.trace_id,
                "token_type": "administrative"
            },
            remediation_suggestions=[
                "Remove tokens from responses",
                "Implement proper token management",
                "Use secure authentication methods"
            ]
        )
    
    def _check_data_exposure(self, trace: NetworkTrace) -> List[Issue]:
        """Check for sensitive data exposure in requests/responses."""
        issues = []
        
        request = self._get_request_data(trace)
        response = self._get_response_data(trace)
        
        # Check request URL for sensitive data
        if request and request.url:
            url_lower = request.url.lower()
            
            # Check for API keys in URL
            if any(pattern in url_lower for pattern in ['api_key=', 'apikey=', 'key=', 'token=']):
                issues.append(self._create_api_key_exposure_issue(trace, request.url))
            
            # Check for sensitive parameters
            if any(pattern in url_lower for pattern in ['ssn=', 'social_security=', 'credit_card=', 'password=']):
                issues.append(self._create_sensitive_param_exposure_issue(trace, request.url))
            
            # Check for debug parameters
            if any(pattern in url_lower for pattern in ['debug=1', 'debug=true', 'include_sensitive=true']):
                issues.append(self._create_debug_param_exposure_issue(trace, request.url))
        
        # Check response body for sensitive data
        if response and response.body:
            response_body = str(response.body).lower()
            
            # Check for PII in response
            if any(pattern in response_body for pattern in ['ssn', 'social security', 'credit_card', 'bank_account']):
                issues.append(self._create_pii_exposure_issue(trace))
            
            # Check for internal data exposure
            if any(pattern in response_body for pattern in ['internal_user_id', 'internal_api_key', 'admin_notes']):
                issues.append(self._create_internal_data_exposure_issue(trace))
        
        return issues
    
    def _check_tracking_indicators(self, trace: NetworkTrace) -> List[Issue]:
        """Check for tracking and analytics indicators."""
        issues = []
        
        request = self._get_request_data(trace)
        response = self._get_response_data(trace)
        
        # Check for tracking URLs
        if request and request.url:
            url_lower = request.url.lower()
            
            # Check for analytics/tracking domains
            tracking_domains = ['analytics', 'tracking', 'third-party-tracker', 'google-analytics', 'facebook']
            if any(domain in url_lower for domain in tracking_domains):
                issues.append(self._create_tracking_request_issue(trace, request.url))
            
            # Check for fingerprinting collection URLs
            if 'fingerprint' in url_lower or 'collect' in url_lower:
                issues.append(self._create_fingerprint_collection_issue(trace, request.url))
        
        # Check request body for comprehensive tracking data
        if request and hasattr(request, 'body') and request.body:
            request_body = str(request.body).lower()
            
            # Check for comprehensive user tracking
            if 'comprehensive_tracking' in request_body or 'user_identification' in request_body:
                issues.append(self._create_comprehensive_tracking_issue(trace))
            
            # Check for behavioral analysis
            if 'behavioral_analysis' in request_body or 'mouse_movements' in request_body:
                issues.append(self._create_behavioral_tracking_issue(trace))
        
        # Check response headers for tracking cookies
        if response and response.headers:
            tracking_cookies = []
            for header in response.headers:
                if header.get('name', '').lower() == 'set-cookie':
                    cookie_value = header.get('value', '').lower()
                    if any(pattern in cookie_value for pattern in ['tracking', 'analytics', '_ga', 'fb_pixel']):
                        tracking_cookies.append(header.get('value'))
            
            if tracking_cookies:
                issues.append(self._create_tracking_cookies_issue(trace, tracking_cookies))
        
        return issues
    
    def _check_debug_leakage(self, trace: NetworkTrace) -> List[Issue]:
        """Check for debug information leakage."""
        issues = []
        
        request = self._get_request_data(trace)
        response = self._get_response_data(trace)
        
        # Check response headers for debug information
        if response and response.headers:
            debug_headers = []
            for header in response.headers:
                header_name = header.get('name', '').lower()
                if any(pattern in header_name for pattern in ['debug', 'x-debug', 'x-database', 'x-memory', 'x-execution']):
                    debug_headers.append(header)
            
            if debug_headers:
                issues.append(self._create_debug_headers_issue(trace, debug_headers))
        
        # Check response body for debug information
        if response and response.body:
            response_body = str(response.body).lower()
            
            # Check for debug mode indicators
            if 'debug mode' in response_body or 'debug_mode' in response_body:
                issues.append(self._create_debug_mode_issue(trace))
            
            # Check for internal system information
            if any(pattern in response_body for pattern in ['database queries', 'memory usage', 'execution time']):
                issues.append(self._create_system_info_leakage_issue(trace))
            
            # Check for admin/internal tokens
            if any(pattern in response_body for pattern in ['admin_token', 'debug_token', 'internal_key']):
                issues.append(self._create_admin_token_leakage_issue(trace))
        
        return issues
    
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
            category=IssueCategory.BROWSER_AUTOMATION,
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
            category=IssueCategory.FINGERPRINTING,
            severity=SeverityLevel.CRITICAL,
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
            category=IssueCategory.BROWSER_AUTOMATION,
            severity=SeverityLevel.HIGH,
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
    
    # New metadata-based helper methods
    def _check_user_agent_from_metadata(self, trace: NetworkTrace, http_request: Dict[str, Any]) -> List[Issue]:
        """Check user agent for automation indicators from metadata."""
        issues = []
        
        headers = http_request.get('headers', [])
        if not headers:
            return issues
        
        user_agent = self._get_header_value(headers, 'user-agent')
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
    
    def _check_automation_headers_from_metadata(self, trace: NetworkTrace, http_request: Dict[str, Any]) -> List[Issue]:
        """Check for automation-revealing headers from metadata."""
        issues = []
        
        headers = http_request.get('headers', [])
        if not headers:
            return issues
        
        automation_headers_found = []
        for header in headers:
            header_name = header.get('name', '').lower()
            if any(auto_header in header_name for auto_header in self.automation_headers):
                automation_headers_found.append(header)
        
        if automation_headers_found:
            issues.append(self._create_automation_headers_issue(trace, automation_headers_found))
        
        return issues
    
    def _check_automation_detection_from_metadata(self, trace: NetworkTrace, http_response: Dict[str, Any]) -> List[Issue]:
        """Check response content for automation detection messages from metadata."""
        issues = []
        
        response_body = http_response.get('body')
        if not response_body:
            return issues
        
        response_body_str = str(response_body).lower()
        
        for pattern in self.automation_patterns:
            if re.search(pattern, response_body_str, re.IGNORECASE):
                issues.append(self._create_automation_detection_issue(trace, pattern))
                break  # Only create one issue per trace to avoid duplicates
        
        return issues
    
    def _check_fingerprinting_attempts_from_metadata(self, trace: NetworkTrace, http_response: Dict[str, Any]) -> List[Issue]:
        """Check for browser fingerprinting attempts from metadata."""
        issues = []
        
        response_body = http_response.get('body')
        if not response_body:
            return issues
        
        response_body_str = str(response_body).lower()
        
        # Check for fingerprinting JavaScript
        fingerprinting_found = []
        for pattern in self.fingerprinting_patterns:
            if re.search(pattern, response_body_str, re.IGNORECASE):
                fingerprinting_found.append(pattern)
        
        if fingerprinting_found:
            issues.append(self._create_fingerprinting_issue(trace, fingerprinting_found))
        
        # Check for specific fingerprinting techniques
        if 'canvas' in response_body_str and ('fingerprint' in response_body_str or 'toDataURL' in response_body_str):
            issues.append(self._create_canvas_fingerprinting_issue(trace))
        
        # Enhanced WebGL fingerprinting detection
        if 'webgl' in response_body_str and ('getparameter' in response_body_str or 'getsupportedextensions' in response_body_str or 'unmasked_vendor_webgl' in response_body_str or 'unmasked_renderer_webgl' in response_body_str):
            issues.append(self._create_webgl_fingerprinting_issue(trace))
        
        return issues
    
    def _check_antibot_challenges_from_metadata(self, trace: NetworkTrace, http_response: Dict[str, Any]) -> List[Issue]:
        """Check for anti-bot challenges from metadata."""
        issues = []
        
        status_code = http_response.get('status_code')
        if not status_code:
            return issues
        
        # Check response status codes
        if status_code in [403, 429, 503]:
            response_body = http_response.get('body', '')
            response_body_str = str(response_body).lower()
            
            # Check for specific anti-bot services
            if any(pattern in response_body_str for pattern in ['cloudflare', 'captcha', 'challenge']):
                issues.append(self._create_antibot_challenge_issue_from_metadata(trace, status_code))
        
        return issues
    
    def _check_javascript_patterns_from_metadata(self, trace: NetworkTrace, http_request: Dict[str, Any]) -> List[Issue]:
        """Check for suspicious JavaScript execution patterns from metadata."""
        issues = []
        
        url = http_request.get('url', '')
        if not url:
            return issues
        
        url_lower = url.lower()
        
        # Check for JavaScript-based detection attempts
        js_detection_patterns = ['detect.js', 'fingerprint.js', 'bot-detection.js', 'detection.js', 'antibot.js', '/js/bot-detection.js']
        if any(js_pattern in url_lower for js_pattern in js_detection_patterns):
            issues.append(self._create_js_detection_issue_from_metadata(trace, url))
        
        # Also check response body for bot detection script content
        http_response = trace.metadata.get('http_response')
        if http_response and http_response.get('body'):
            response_body = str(http_response['body']).lower()
            if 'bot detection script' in response_body or 'detection script' in response_body:
                issues.append(self._create_js_detection_issue_from_metadata(trace, url))
        
        return issues
    
    def _has_automation_detection_indicators_from_metadata(self, trace: NetworkTrace) -> bool:
        """Check if trace has automation detection indicators from metadata."""
        http_response = trace.metadata.get('http_response')
        if http_response and http_response.get('body'):
            response_body = str(http_response['body']).lower()
            return any(
                re.search(pattern, response_body, re.IGNORECASE) 
                for pattern in self.automation_patterns
            )
        return False
    
    def _create_antibot_challenge_issue_from_metadata(self, trace: NetworkTrace, status_code: int) -> Issue:
        """Create issue for anti-bot challenge from metadata."""
        evidence = [
            self._create_evidence(
                "antibot_response",
                "Anti-bot challenge response",
                f"Status: {status_code}",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        return self._create_issue(
            title="Anti-Bot Challenge Triggered",
            description=f"Anti-bot protection triggered (HTTP {status_code})",
            category=IssueCategory.BROWSER_CONFIG,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "anti_bot_challenge",
                "trace_id": trace.trace_id,
                "status_code": status_code
            },
            remediation_suggestions=[
                "Implement CAPTCHA solving",
                "Use residential IP addresses",
                "Add human-like delays",
                "Solve challenges manually"
            ]
        )
    
    def _create_js_detection_issue_from_metadata(self, trace: NetworkTrace, url: str) -> Issue:
        """Create issue for JavaScript-based detection from metadata."""
        evidence = [
            self._create_evidence(
                "js_detection_url",
                "JavaScript detection script URL",
                url,
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        # Extract filename from URL for description
        filename = url.split('/')[-1] if '/' in url else url
        
        return self._create_issue(
            title="JavaScript-Based Detection Script",
            description=f"Request to JavaScript script designed for bot detection: {filename}",
            category=IssueCategory.FINGERPRINTING,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,  # Increased confidence for reliable URL-based detection
            evidence=evidence,
            metadata={
                "rule_id": "browser_fingerprinting",
                "trace_id": trace.trace_id,
                "detection_url": url
            },
            remediation_suggestions=[
                "Block detection scripts",
                "Use script blocking extensions",
                "Modify JavaScript execution environment"
            ]
        )
