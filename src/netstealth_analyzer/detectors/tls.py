"""
TLS fingerprinting and security detector.

This module detects TLS-related stealth issues including fingerprinting risks,
certificate problems, and cipher suite weaknesses with full async support.
"""

import time
from typing import Any, AsyncIterator, Dict, List, Optional, Set
from datetime import datetime, timezone

from .base import BaseDetector, DetectionContext, DetectionResult
from ..models.issues import Issue, IssueEvidence, DetectionRule
from ..models.enums import SeverityLevel, IssueCategory, DetectionConfidence
from ..models.network import NetworkTrace, TLSInfo


class TlsDetector(BaseDetector):
    """
    Detector for TLS fingerprinting and security issues.
    
    Analyzes TLS configurations, certificates, cipher suites, and protocol versions
    to identify potential stealth risks and security vulnerabilities.
    """
    
    def __init__(self, event_bus=None, confidence_threshold=0.7):
        """Initialize TLS detector."""
        super().__init__(event_bus, confidence_threshold)
        
        # TLS fingerprinting indicators
        self.ja3_fingerprint_patterns = [
            # Common automation signatures
            'selenium', 'chromedriver', 'puppeteer', 'playwright',
            # Unusual cipher combinations that might indicate automation
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        ]
        
        # Weak/deprecated elements - map enum values to strings for comparison
        self.weak_tls_versions = ['ssl_2.0', 'ssl_3.0', 'tls_1.0', 'tls_1.1', 'SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
        self.weak_cipher_suites = [
            'TLS_RSA_WITH_RC4_128_MD5',
            'TLS_RSA_WITH_RC4_128_SHA',
            'TLS_RSA_WITH_DES_CBC_SHA',
            'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
            'TLS_DHE_RSA_WITH_DES_CBC_SHA'
        ]
        
        # Certificate validation patterns
        self.suspicious_certificate_issuers = [
            'Let\'s Encrypt',  # Not inherently suspicious but automated
            'ISRG Root X1',
            'Self-signed'
        ]
        
        # Detection rules
        self._detection_rules = [
            DetectionRule(
                id="tls_weak_version",
                name="Weak TLS Version",
                pattern=r"(SSLv[23]|TLSv1\.[01])",
                description="Detected use of deprecated or weak TLS version",
                category=IssueCategory.TLS_FINGERPRINT,
                severity=SeverityLevel.HIGH,
                confidence=DetectionConfidence.HIGH
            ),
            DetectionRule(
                id="tls_weak_cipher",
                name="Weak Cipher Suite",
                pattern=r"(RC4|DES|3DES|MD5).*(_SHA|_MD5)",
                description="Detected use of weak or deprecated cipher suite",
                category=IssueCategory.TLS_FINGERPRINT,
                severity=SeverityLevel.MEDIUM,
                confidence=DetectionConfidence.HIGH
            ),
            DetectionRule(
                id="tls_fingerprint_risk",
                name="TLS Fingerprinting Risk",
                pattern=r"(selenium|chromedriver|puppeteer|playwright)",
                description="TLS configuration may be fingerprintable",
                category=IssueCategory.TLS_FINGERPRINT,
                severity=SeverityLevel.MEDIUM,
                confidence=DetectionConfidence.MEDIUM
            ),
            DetectionRule(
                id="tls_certificate_issue",
                name="Certificate Security Issue",
                pattern=r"(expired|invalid|untrusted|self-signed)",
                description="Certificate has security or trust issues",
                category=IssueCategory.TLS_FINGERPRINT,
                severity=SeverityLevel.HIGH,
                confidence=DetectionConfidence.HIGH
            ),
            DetectionRule(
                id="tls_automation_signature",
                name="Automation TLS Signature",
                pattern=r"(webdriver|automation|headless|chrome_automation)",
                description="TLS handshake indicates automated browser",
                category=IssueCategory.BROWSER_CONFIG,
                severity=SeverityLevel.HIGH,
                confidence=DetectionConfidence.HIGH
            )
        ]
    
    @property
    def name(self) -> str:
        """Get detector name."""
        return "TLS Security Detector"
    
    @property
    def version(self) -> str:
        """Get detector version."""
        return "2.0.0"
    
    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects TLS fingerprinting risks, weak security configurations, and automation signatures"
    
    @property
    def categories(self) -> List[IssueCategory]:
        """Get issue categories this detector can identify."""
        return [
            IssueCategory.TLS_FINGERPRINT,
            IssueCategory.BROWSER_CONFIG
        ]
    
    @property
    def detection_rules(self) -> List[DetectionRule]:
        """Get detection rules used by this detector."""
        return self._detection_rules
    
    async def detect(self, context: DetectionContext) -> DetectionResult:
        """
        Perform TLS detection on the provided context.
        
        Args:
            context: Detection context with traces and configuration
            
        Returns:
            DetectionResult with found TLS issues and statistics
        """
        start_time = time.time()
        await self._emit_progress("tls_detection_started", {"traces": len(context.network_traces)})
        
        # Initialize results
        issues = []
        statistics = self._init_statistics()
        errors = []
        rules_applied = []
        
        try:
            # Analyze each network trace for TLS issues
            for trace_idx, trace in enumerate(context.network_traces):
                statistics['traces_analyzed'] += 1
                
                try:
                    trace_issues = await self._analyze_trace_tls(trace, context)
                    issues.extend(trace_issues)
                    
                    # Track rules applied
                    for issue in trace_issues:
                        # Extract rule_id from issue raw_data (this is where we store it)
                        rule_id = None
                        if hasattr(issue, 'raw_data') and isinstance(issue.raw_data, dict):
                            rule_id = issue.raw_data.get('rule_id')
                        
                        if rule_id and rule_id not in [r.id for r in rules_applied]:
                            rule = next((r for r in self._detection_rules if r.id == rule_id), None)
                            if rule:
                                rules_applied.append(rule)
                    
                    # Emit progress every 100 traces
                    if (trace_idx + 1) % 100 == 0:
                        await self._emit_progress("tls_traces_processed", {
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
            
            await self._emit_progress("tls_detection_completed", {
                "issues_found": len(high_confidence_issues),
                "processing_time_ms": statistics['processing_time_ms']
            })
            
            return result
            
        except Exception as e:
            await self._emit_progress("tls_detection_failed", {"error": str(e)})
            raise RuntimeError(f"TLS detection failed: {e}")
    
    async def _analyze_trace_tls(
        self, 
        trace: NetworkTrace, 
        context: DetectionContext
    ) -> List[Issue]:
        """
        Analyze a single network trace for TLS issues.
        
        Args:
            trace: Network trace to analyze
            context: Detection context
            
        Returns:
            List of TLS-related issues found
        """
        issues = []
        
        # Get TLS information from connection info or metadata
        tls_info = None
        if hasattr(trace, 'connection_info') and trace.connection_info and hasattr(trace.connection_info, 'tls_info') and trace.connection_info.tls_info:
            tls_info = trace.connection_info.tls_info
        elif hasattr(trace, 'tls_info'):
            tls_info = trace.tls_info
        
        if not tls_info:
            return issues
        
        # Check for weak TLS versions
        if tls_info.version:
            version_str = tls_info.version.value if hasattr(tls_info.version, 'value') else str(tls_info.version)
            if version_str in self.weak_tls_versions:
                issues.append(self._create_weak_tls_version_issue(trace, tls_info))
        
        # Check for weak cipher suites
        if tls_info.cipher_suite and any(
            weak_cipher in str(tls_info.cipher_suite) 
            for weak_cipher in self.weak_cipher_suites
        ):
            issues.append(self._create_weak_cipher_issue(trace, tls_info))
        
        # Check for certificate issues
        if hasattr(tls_info, 'certificate_issues') and tls_info.certificate_issues:
            issues.append(self._create_certificate_issue(trace, tls_info))
        
        # Check for fingerprinting risks
        fingerprint_risk = self._assess_fingerprinting_risk(tls_info)
        if fingerprint_risk > 0.5:
            issues.append(self._create_fingerprinting_risk_issue(trace, tls_info, fingerprint_risk))
        
        # Check for automation signatures
        if self._detect_automation_signature(tls_info):
            issues.append(self._create_automation_signature_issue(trace, tls_info))
        
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
            List of cross-trace TLS issues
        """
        issues = []
        
        # Extract TLS info from all traces
        tls_infos = []
        for trace in traces:
            tls_info = None
            if hasattr(trace, 'connection_info') and trace.connection_info:
                tls_info = trace.connection_info.tls_info
            elif hasattr(trace, 'tls_info'):
                tls_info = trace.tls_info
            
            if tls_info:
                tls_infos.append((trace, tls_info))
        
        if len(tls_infos) < 2:
            return issues
        
        # Check for consistent TLS fingerprints (suspicious)
        fingerprint_consistency = self._check_fingerprint_consistency(tls_infos)
        if fingerprint_consistency > 0.8:
            issues.append(self._create_consistent_fingerprint_issue(traces, fingerprint_consistency))
        
        # Check for unusual handshake patterns
        unusual_patterns = self._detect_unusual_handshake_patterns(tls_infos)
        if unusual_patterns:
            issues.append(self._create_unusual_pattern_issue(traces, unusual_patterns))
        
        return issues
    
    def _create_weak_tls_version_issue(self, trace: NetworkTrace, tls_info: TLSInfo) -> Issue:
        """Create issue for weak TLS version."""
        version_str = tls_info.version.value if hasattr(tls_info.version, 'value') else str(tls_info.version)
        
        evidence = [
            self._create_evidence(
                "tls_version",
                "Detected TLS version",
                version_str,
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        issue = self._create_issue(
            title="Weak TLS Version Detected",
            description=f"Connection uses deprecated TLS version {version_str}. "
                       f"This version has known security vulnerabilities and should be avoided.",
            category=IssueCategory.TLS_FINGERPRINT,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.VERY_HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "tls_weak_version",
                "trace_id": trace.trace_id,
                "tls_version": version_str
            },
            remediation_suggestions=[
                "Upgrade to TLS 1.2 or higher",
                "Disable support for deprecated TLS versions",
                "Use modern cipher suites"
            ]
        )
        # Store rule_id in raw_data for tracking
        issue.raw_data["rule_id"] = "tls_weak_version"
        return issue
    
    def _create_weak_cipher_issue(self, trace: NetworkTrace, tls_info: TLSInfo) -> Issue:
        """Create issue for weak cipher suite."""
        evidence = [
            self._create_evidence(
                "cipher_suite",
                "Detected cipher suite",
                str(tls_info.cipher_suite),
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        issue = self._create_issue(
            title="Weak Cipher Suite Detected",
            description=f"Connection uses weak cipher suite {tls_info.cipher_suite}. "
                       f"This cipher has known vulnerabilities or provides insufficient security.",
            category=IssueCategory.TLS_FINGERPRINT,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "tls_weak_cipher",
                "trace_id": trace.trace_id,
                "cipher_suite": str(tls_info.cipher_suite)
            },
            remediation_suggestions=[
                "Use AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)",
                "Disable weak cipher suites in server configuration",
                "Prioritize strong cipher suites"
            ]
        )
        # Store rule_id in raw_data for tracking
        issue.raw_data["rule_id"] = "tls_weak_cipher"
        return issue
    
    def _create_certificate_issue(self, trace: NetworkTrace, tls_info: TLSInfo) -> Issue:
        """Create issue for certificate problems."""
        evidence = [
            self._create_evidence(
                "certificate_issues",
                "Certificate problems detected",
                ", ".join(tls_info.certificate_issues),
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        severity = SeverityLevel.HIGH if any(
            issue.lower() in ['expired', 'invalid', 'untrusted'] 
            for issue in tls_info.certificate_issues
        ) else SeverityLevel.MEDIUM
        
        issue = self._create_issue(
            title="Certificate Security Issue",
            description=f"Certificate has the following issues: {', '.join(tls_info.certificate_issues)}",
            category=IssueCategory.TLS_FINGERPRINT,
            severity=severity,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "tls_certificate_issue",
                "trace_id": trace.trace_id,
                "certificate_issues": tls_info.certificate_issues
            },
            remediation_suggestions=[
                "Verify certificate chain is complete and valid",
                "Ensure certificate is from trusted CA",
                "Check certificate expiration date"
            ]
        )
        # Store rule_id in raw_data for tracking
        issue.raw_data["rule_id"] = "tls_certificate_issue"
        return issue
    
    def _create_fingerprinting_risk_issue(
        self, 
        trace: NetworkTrace, 
        tls_info: TLSInfo, 
        risk_score: float
    ) -> Issue:
        """Create issue for TLS fingerprinting risk."""
        evidence = [
            self._create_evidence(
                "fingerprint_risk_score",
                "Calculated fingerprinting risk score",
                f"{risk_score:.2f}",
                metadata={"trace_id": trace.trace_id}
            )
        ]
        
        if tls_info.cipher_suite:
            evidence.append(self._create_evidence(
                "cipher_suite",
                "Cipher suite configuration",
                str(tls_info.cipher_suite)
            ))
        
        issue = self._create_issue(
            title="TLS Fingerprinting Risk",
            description=f"TLS configuration has unique characteristics that may allow fingerprinting "
                       f"(risk score: {risk_score:.2f}). This could be used to identify the client.",
            category=IssueCategory.TLS_FINGERPRINT,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "tls_fingerprint_risk",
                "trace_id": trace.trace_id,
                "risk_score": risk_score
            },
            remediation_suggestions=[
                "Use common TLS configurations",
                "Randomize cipher suite ordering",
                "Use TLS randomization tools"
            ]
        )
        # Store rule_id in raw_data for tracking
        issue.raw_data["rule_id"] = "tls_fingerprint_risk"
        return issue
    
    def _create_automation_signature_issue(self, trace: NetworkTrace, tls_info: TLSInfo) -> Issue:
        """Create issue for automation signature detection."""
        evidence = [
            self._create_evidence(
                "automation_indicators",
                "Detected automation signatures in TLS handshake",
                "TLS handshake characteristics match known automation tools"
            )
        ]
        
        issue = self._create_issue(
            title="Browser Automation Signature Detected",
            description="TLS handshake contains signatures that indicate automated browser usage. "
                       "This may trigger anti-automation defenses.",
            category=IssueCategory.BROWSER_CONFIG,
            severity=SeverityLevel.HIGH,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "tls_automation_signature",
                "trace_id": trace.trace_id
            },
            remediation_suggestions=[
                "Use stealth mode in browser automation",
                "Modify TLS handshake parameters",
                "Use real browser profiles for TLS configuration"
            ]
        )
        # Store rule_id in raw_data for tracking
        issue.raw_data["rule_id"] = "tls_automation_signature"
        return issue
    
    def _create_consistent_fingerprint_issue(
        self, 
        traces: List[NetworkTrace], 
        consistency_score: float
    ) -> Issue:
        """Create issue for overly consistent TLS fingerprints."""
        evidence = [
            self._create_evidence(
                "fingerprint_consistency",
                "TLS fingerprint consistency across connections",
                f"{consistency_score:.2f}",
                metadata={"analyzed_traces": len(traces)}
            )
        ]
        
        issue = self._create_issue(
            title="Suspicious TLS Fingerprint Consistency",
            description=f"TLS fingerprints are unusually consistent across {len(traces)} connections "
                       f"(consistency: {consistency_score:.2f}). This may indicate automation.",
            category=IssueCategory.TLS_FINGERPRINT,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "tls_fingerprint_risk",
                "consistency_score": consistency_score,
                "trace_count": len(traces)
            },
            remediation_suggestions=[
                "Introduce TLS parameter randomization",
                "Use different browser profiles",
                "Vary connection timing"
            ]
        )
        # Store rule_id in raw_data for tracking
        issue.raw_data["rule_id"] = "tls_fingerprint_risk"
        return issue
    
    def _create_unusual_pattern_issue(
        self, 
        traces: List[NetworkTrace], 
        patterns: List[str]
    ) -> Issue:
        """Create issue for unusual TLS patterns."""
        evidence = [
            self._create_evidence(
                "unusual_patterns",
                "Detected unusual TLS handshake patterns",
                ", ".join(patterns)
            )
        ]
        
        issue = self._create_issue(
            title="Unusual TLS Handshake Patterns",
            description=f"Detected unusual patterns in TLS handshakes: {', '.join(patterns)}",
            category=IssueCategory.TLS_FINGERPRINT,
            severity=SeverityLevel.LOW,
            confidence=DetectionConfidence.HIGH,
            evidence=evidence,
            metadata={
                "rule_id": "tls_fingerprint_risk",
                "patterns": patterns,
                "trace_count": len(traces)
            },
            remediation_suggestions=[
                "Review TLS configuration for unusual settings",
                "Use standard browser TLS parameters",
                "Test with different TLS libraries"
            ]
        )
        # Store rule_id in raw_data for tracking
        issue.raw_data["rule_id"] = "tls_fingerprint_risk"
        return issue
    
    def _assess_fingerprinting_risk(self, tls_info: TLSInfo) -> float:
        """
        Assess TLS fingerprinting risk based on configuration uniqueness.
        
        Args:
            tls_info: TLS information to analyze
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        risk_factors = []
        
        # Check for unusual cipher combinations
        if tls_info.cipher_suite:
            cipher_str = str(tls_info.cipher_suite).lower()
            if any(pattern.lower() in cipher_str for pattern in self.ja3_fingerprint_patterns):
                risk_factors.append(0.8)
        
        # Check for unusual extension combinations
        if tls_info.extensions:
            extension_count = len(tls_info.extensions)
            if extension_count > 15 or extension_count < 5:
                risk_factors.append(0.6)
        
        # Check for unusual supported groups
        if tls_info.supported_groups:
            if len(tls_info.supported_groups) > 10:
                risk_factors.append(0.4)
        
        # Check for very fast handshake (might indicate caching/automation)
        if tls_info.handshake_duration_ms is not None and tls_info.handshake_duration_ms < 10:
            risk_factors.append(0.5)
        
        return max(risk_factors) if risk_factors else 0.0
    
    def _detect_automation_signature(self, tls_info: TLSInfo) -> bool:
        """
        Detect if TLS configuration indicates browser automation.
        
        Args:
            tls_info: TLS information to analyze
            
        Returns:
            True if automation signatures detected
        """
        # Check cipher suite patterns known to automation tools
        if tls_info.cipher_suite:
            cipher_str = str(tls_info.cipher_suite).lower()
            for pattern in self.ja3_fingerprint_patterns:
                if pattern.lower() in cipher_str:
                    return True
        
        # Check for automation-specific extension combinations
        if tls_info.extensions:
            extensions_str = " ".join(tls_info.extensions).lower()
            automation_indicators = [
                'webdriver', 'automation', 'headless', 'chrome_automation'
            ]
            if any(indicator in extensions_str for indicator in automation_indicators):
                return True
        
        # Check for very consistent handshake timing (robotic behavior)
        if (tls_info.handshake_duration_ms and 
            15 <= tls_info.handshake_duration_ms <= 25):  # Very narrow range
            return True
        
        return False
    
    def _check_fingerprint_consistency(
        self, 
        tls_infos: List[tuple[NetworkTrace, TLSInfo]]
    ) -> float:
        """
        Check consistency of TLS fingerprints across connections.
        
        Args:
            tls_infos: List of (trace, tls_info) tuples
            
        Returns:
            Consistency score between 0.0 and 1.0
        """
        if len(tls_infos) < 2:
            return 0.0
        
        # Extract fingerprint elements
        cipher_suites = []
        extensions_sets = []
        versions = []
        
        for trace, tls_info in tls_infos:
            if tls_info.cipher_suite:
                cipher_suites.append(str(tls_info.cipher_suite))
            if tls_info.extensions:
                extensions_sets.append(set(tls_info.extensions))
            if tls_info.version:
                versions.append(str(tls_info.version))
        
        consistency_factors = []
        
        # Check cipher suite consistency
        if cipher_suites:
            unique_ciphers = len(set(cipher_suites))
            consistency_factors.append(1.0 - (unique_ciphers - 1) / len(cipher_suites))
        
        # Check extension consistency
        if extensions_sets and len(extensions_sets) > 1:
            # Calculate Jaccard similarity for extensions
            similarities = []
            for i in range(len(extensions_sets)):
                for j in range(i + 1, len(extensions_sets)):
                    intersection = len(extensions_sets[i] & extensions_sets[j])
                    union = len(extensions_sets[i] | extensions_sets[j])
                    if union > 0:
                        similarities.append(intersection / union)
            
            if similarities:
                consistency_factors.append(sum(similarities) / len(similarities))
        
        # Check version consistency
        if versions:
            unique_versions = len(set(versions))
            consistency_factors.append(1.0 - (unique_versions - 1) / len(versions))
        
        return sum(consistency_factors) / len(consistency_factors) if consistency_factors else 0.0
    
    def _detect_unusual_handshake_patterns(
        self, 
        tls_infos: List[tuple[NetworkTrace, TLSInfo]]
    ) -> List[str]:
        """
        Detect unusual patterns in TLS handshakes.
        
        Args:
            tls_infos: List of (trace, tls_info) tuples
            
        Returns:
            List of detected unusual patterns
        """
        patterns = []
        
        # Check for unusual timing patterns
        handshake_times = [
            tls_info.handshake_duration_ms 
            for trace, tls_info in tls_infos 
            if tls_info.handshake_duration_ms and tls_info.handshake_duration_ms > 0
        ]
        
        if len(handshake_times) > 1:
            # Very consistent timing might indicate automation
            time_variance = max(handshake_times) - min(handshake_times)
            if time_variance < 5 and len(handshake_times) > 3:
                patterns.append("extremely_consistent_handshake_timing")
            
            # All very fast handshakes might indicate local testing/automation
            if all(t < 20 for t in handshake_times):
                patterns.append("consistently_fast_handshakes")
        
        # Check for unusual cipher suite progressions
        cipher_suites = [
            str(tls_info.cipher_suite) 
            for trace, tls_info in tls_infos 
            if tls_info.cipher_suite
        ]
        
        if len(set(cipher_suites)) == 1 and len(cipher_suites) > 5:
            patterns.append("identical_cipher_suite_across_all_connections")
        
        return patterns
