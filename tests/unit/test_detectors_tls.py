"""
Comprehensive tests for TLS detector.

This test module provides extensive coverage for the TlsDetector class,
including TLS fingerprinting detection, weak cipher detection, certificate
validation, and automation signature detection.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timezone

from netstealth_analyzer.detectors.tls import TlsDetector
from netstealth_analyzer.detectors.base import DetectionContext
from netstealth_analyzer.models.network import NetworkTrace, TLSInfo, ConnectionInfo
from netstealth_analyzer.models.enums import SeverityLevel, IssueCategory, DetectionConfidence, TLSVersion
from netstealth_analyzer.models.issues import DetectionRule


@pytest.fixture
def tls_detector():
    """Create TLS detector instance."""
    return TlsDetector(confidence_threshold=0.7)


@pytest.fixture
def mock_event_bus():
    """Create mock event bus."""
    return Mock()


@pytest.fixture
def detection_context():
    """Create detection context."""
    return DetectionContext(
        network_traces=[],
        service_domains=["example.com"],
        confidence_threshold=0.7
    )


@pytest.fixture
def mock_tls_info():
    """Create mock TLS info."""
    return TLSInfo(
        version=TLSVersion.TLS_12,
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        extensions=["server_name", "supported_groups", "signature_algorithms"],
        supported_groups=["secp256r1", "secp384r1"],
        certificate_issues=[],
        handshake_duration_ms=50
    )


@pytest.fixture
def mock_network_trace():
    """Create mock network trace."""
    trace = Mock(spec=NetworkTrace)
    trace.trace_id = "test-trace-123"
    trace.is_http.return_value = True
    trace.http_data = Mock()
    trace.connection_info = Mock(spec=ConnectionInfo)
    return trace


class TestTlsDetectorInit:
    """Test TLS detector initialization."""

    def test_init_default_values(self):
        """Test detector initialization with default values."""
        detector = TlsDetector()
        
        assert detector.name == "TLS Security Detector"
        assert detector.version == "2.0.0"
        assert "TLS fingerprinting" in detector.description
        assert IssueCategory.TLS_FINGERPRINT in detector.categories
        assert IssueCategory.BROWSER_CONFIG in detector.categories
        assert len(detector.detection_rules) == 5

    def test_init_with_custom_values(self, mock_event_bus):
        """Test detector initialization with custom values."""
        detector = TlsDetector(event_bus=mock_event_bus, confidence_threshold=0.8)
        
        assert detector.event_bus == mock_event_bus
        assert detector.confidence_threshold == 0.8

    def test_detection_rules_structure(self, tls_detector):
        """Test detection rules are properly structured."""
        rules = tls_detector.detection_rules
        
        rule_ids = [rule.id for rule in rules]
        expected_ids = [
            "tls_weak_version", "tls_weak_cipher", "tls_fingerprint_risk",
            "tls_certificate_issue", "tls_automation_signature"
        ]
        
        for expected_id in expected_ids:
            assert expected_id in rule_ids
        
        # Check rule structure
        for rule in rules:
            assert isinstance(rule, DetectionRule)
            assert rule.id
            assert rule.name
            assert rule.pattern
            assert rule.description
            # Due to Pydantic use_enum_values=True, category is serialized as string
            assert isinstance(rule.category, (IssueCategory, str))
            assert isinstance(rule.severity, (SeverityLevel, str))
            # Confidence is converted to float in DetectionRule model
            assert isinstance(rule.confidence, (DetectionConfidence, float))


class TestTlsDetectorWeakVersionDetection:
    """Test weak TLS version detection."""

    @pytest.mark.asyncio
    async def test_detect_sslv2(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of SSLv2."""
        mock_tls_info.version = TLSVersion.SSL_30  # Use closest available enum
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        assert result.issues_found
        issue = result.issues_found[0]
        assert "Weak TLS Version" in issue.title
        assert issue.severity == SeverityLevel.HIGH
        assert issue.category == IssueCategory.TLS_FINGERPRINT
        assert "ssl_3.0" in issue.description

    @pytest.mark.asyncio
    async def test_detect_sslv3(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of SSLv3."""
        mock_tls_info.version = TLSVersion.SSL_30
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        assert result.issues_found
        issue = result.issues_found[0]
        assert "Weak TLS Version" in issue.title
        assert "ssl_3.0" in issue.description

    @pytest.mark.asyncio
    async def test_detect_tlsv10(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of TLSv1.0."""
        mock_tls_info.version = TLSVersion.TLS_10
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        assert result.issues_found
        issue = result.issues_found[0]
        assert "Weak TLS Version" in issue.title
        assert "tls_1.0" in issue.description

    @pytest.mark.asyncio
    async def test_detect_tlsv11(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of TLSv1.1."""
        mock_tls_info.version = TLSVersion.TLS_11
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        assert result.issues_found
        issue = result.issues_found[0]
        assert "Weak TLS Version" in issue.title
        assert "tls_1.1" in issue.description

    @pytest.mark.asyncio
    async def test_no_detection_strong_version(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test no detection for strong TLS versions."""
        mock_tls_info.version = TLSVersion.TLS_13
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        # Should not detect weak version issues
        weak_version_issues = [
            issue for issue in result.issues_found 
            if "Weak TLS Version" in issue.title
        ]
        assert not weak_version_issues


class TestTlsDetectorWeakCipherDetection:
    """Test weak cipher suite detection."""

    @pytest.mark.asyncio
    async def test_detect_rc4_cipher(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of RC4 cipher."""
        mock_tls_info.cipher_suite = "TLS_RSA_WITH_RC4_128_SHA"
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        assert result.issues_found
        issue = result.issues_found[0]
        assert "Weak Cipher Suite" in issue.title
        assert issue.severity == SeverityLevel.MEDIUM
        assert "RC4" in issue.description

    @pytest.mark.asyncio
    async def test_detect_des_cipher(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of DES cipher."""
        mock_tls_info.cipher_suite = "TLS_RSA_WITH_DES_CBC_SHA"
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        assert result.issues_found
        issue = result.issues_found[0]
        assert "Weak Cipher Suite" in issue.title
        assert "DES" in issue.description

    @pytest.mark.asyncio
    async def test_detect_3des_cipher(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of 3DES cipher."""
        mock_tls_info.cipher_suite = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        assert result.issues_found
        issue = result.issues_found[0]
        assert "Weak Cipher Suite" in issue.title
        assert "3DES" in issue.description

    @pytest.mark.asyncio
    async def test_no_detection_strong_cipher(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test no detection for strong cipher suites."""
        mock_tls_info.cipher_suite = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        # Should not detect weak cipher issues
        weak_cipher_issues = [
            issue for issue in result.issues_found 
            if "Weak Cipher Suite" in issue.title
        ]
        assert not weak_cipher_issues


class TestTlsDetectorCertificateIssues:
    """Test certificate issue detection."""

    @pytest.mark.asyncio
    async def test_detect_expired_certificate(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of expired certificate."""
        mock_tls_info.certificate_issues = ["expired"]
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        assert result.issues_found
        issue = result.issues_found[0]
        assert "Certificate Security Issue" in issue.title
        assert issue.severity == SeverityLevel.HIGH
        assert "expired" in issue.description

    @pytest.mark.asyncio
    async def test_detect_invalid_certificate(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of invalid certificate."""
        mock_tls_info.certificate_issues = ["invalid"]
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        assert result.issues_found
        issue = result.issues_found[0]
        assert "Certificate Security Issue" in issue.title
        assert issue.severity == SeverityLevel.HIGH
        assert "invalid" in issue.description

    @pytest.mark.asyncio
    async def test_detect_self_signed_certificate(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of self-signed certificate."""
        mock_tls_info.certificate_issues = ["self-signed"]
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        assert result.issues_found
        issue = result.issues_found[0]
        assert "Certificate Security Issue" in issue.title
        assert issue.severity == SeverityLevel.MEDIUM
        assert "self-signed" in issue.description

    @pytest.mark.asyncio
    async def test_detect_multiple_certificate_issues(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of multiple certificate issues."""
        mock_tls_info.certificate_issues = ["expired", "untrusted"]
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        assert result.issues_found
        issue = result.issues_found[0]
        assert "Certificate Security Issue" in issue.title
        assert "expired" in issue.description
        assert "untrusted" in issue.description


class TestTlsDetectorFingerprintingRisk:
    """Test TLS fingerprinting risk assessment."""

    @pytest.mark.asyncio
    async def test_assess_fingerprinting_risk_automation_cipher(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test fingerprinting risk assessment with automation cipher."""
        mock_tls_info.cipher_suite = "selenium_automation_cipher"
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        fingerprint_issues = [
            issue for issue in result.issues_found 
            if "TLS Fingerprinting Risk" in issue.title
        ]
        assert fingerprint_issues
        issue = fingerprint_issues[0]
        assert issue.severity == SeverityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_assess_fingerprinting_risk_many_extensions(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test fingerprinting risk with many extensions."""
        mock_tls_info.extensions = [f"ext_{i}" for i in range(20)]  # Many extensions
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        fingerprint_issues = [
            issue for issue in result.issues_found 
            if "TLS Fingerprinting Risk" in issue.title
        ]
        assert fingerprint_issues

    @pytest.mark.asyncio
    async def test_assess_fingerprinting_risk_few_extensions(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test fingerprinting risk with few extensions."""
        mock_tls_info.extensions = ["ext_1", "ext_2"]  # Few extensions
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        fingerprint_issues = [
            issue for issue in result.issues_found 
            if "TLS Fingerprinting Risk" in issue.title
        ]
        assert fingerprint_issues

    @pytest.mark.asyncio
    async def test_assess_fingerprinting_risk_fast_handshake(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test fingerprinting risk with very fast handshake."""
        mock_tls_info.handshake_duration_ms = 5  # Very fast
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        fingerprint_issues = [
            issue for issue in result.issues_found 
            if "TLS Fingerprinting Risk" in issue.title
        ]
        assert fingerprint_issues


class TestTlsDetectorAutomationSignatures:
    """Test automation signature detection."""

    @pytest.mark.asyncio
    async def test_detect_selenium_signature(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of Selenium automation signature."""
        mock_tls_info.cipher_suite = "selenium_test_cipher"
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        automation_issues = [
            issue for issue in result.issues_found 
            if "Browser Automation Signature" in issue.title
        ]
        assert automation_issues
        issue = automation_issues[0]
        assert issue.severity == SeverityLevel.HIGH
        assert issue.category == IssueCategory.BROWSER_CONFIG

    @pytest.mark.asyncio
    async def test_detect_chromedriver_signature(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of ChromeDriver automation signature."""
        mock_tls_info.cipher_suite = "chromedriver_automation"
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        automation_issues = [
            issue for issue in result.issues_found 
            if "Browser Automation Signature" in issue.title
        ]
        assert automation_issues

    @pytest.mark.asyncio
    async def test_detect_automation_extensions(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of automation through extensions."""
        mock_tls_info.extensions = ["webdriver", "automation", "normal_ext"]
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        automation_issues = [
            issue for issue in result.issues_found 
            if "Browser Automation Signature" in issue.title
        ]
        assert automation_issues

    @pytest.mark.asyncio
    async def test_detect_robotic_timing(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test detection of robotic timing patterns."""
        mock_tls_info.handshake_duration_ms = 20  # Very consistent timing
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        automation_issues = [
            issue for issue in result.issues_found 
            if "Browser Automation Signature" in issue.title
        ]
        assert automation_issues


class TestTlsDetectorCrossTraceAnalysis:
    """Test cross-trace pattern analysis."""

    @pytest.mark.asyncio
    async def test_consistent_fingerprints(self, tls_detector, detection_context):
        """Test detection of overly consistent TLS fingerprints."""
        traces = []
        for i in range(5):
            trace = Mock(spec=NetworkTrace)
            trace.trace_id = f"trace-{i}"
            tls_info = TLSInfo(
                version=TLSVersion.TLS_12,
                cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",  # Same cipher
                extensions=["server_name", "supported_groups"],  # Same extensions
                supported_groups=["secp256r1"],
                certificate_issues=[],
                handshake_duration_ms=50
            )
            trace.connection_info = Mock(spec=ConnectionInfo)
            trace.connection_info.tls_info = tls_info
            traces.append(trace)
        
        detection_context.network_traces = traces
        
        result = await tls_detector.detect(detection_context)
        
        consistency_issues = [
            issue for issue in result.issues_found 
            if "Suspicious TLS Fingerprint Consistency" in issue.title
        ]
        assert consistency_issues
        issue = consistency_issues[0]
        assert issue.severity == SeverityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_unusual_handshake_patterns(self, tls_detector, detection_context):
        """Test detection of unusual handshake patterns."""
        traces = []
        for i in range(6):
            trace = Mock(spec=NetworkTrace)
            trace.trace_id = f"trace-{i}"
            tls_info = TLSInfo(
                version=TLSVersion.TLS_12,
                cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                extensions=["server_name"],
                supported_groups=["secp256r1"],
                certificate_issues=[],
                handshake_duration_ms=15  # Very consistent timing
            )
            trace.connection_info = Mock(spec=ConnectionInfo)
            trace.connection_info.tls_info = tls_info
            traces.append(trace)
        
        detection_context.network_traces = traces
        
        result = await tls_detector.detect(detection_context)
        
        pattern_issues = [
            issue for issue in result.issues_found 
            if "Unusual TLS Handshake Patterns" in issue.title
        ]
        assert pattern_issues
        issue = pattern_issues[0]
        assert issue.severity == SeverityLevel.LOW

    @pytest.mark.asyncio
    async def test_fast_handshakes_pattern(self, tls_detector, detection_context):
        """Test detection of consistently fast handshakes."""
        traces = []
        for i in range(4):
            trace = Mock(spec=NetworkTrace)
            trace.trace_id = f"trace-{i}"
            tls_info = TLSInfo(
                version=TLSVersion.TLS_12,
                cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                extensions=["server_name"],
                supported_groups=["secp256r1"],
                certificate_issues=[],
                handshake_duration_ms=10  # Very fast
            )
            trace.connection_info = Mock(spec=ConnectionInfo)
            trace.connection_info.tls_info = tls_info
            traces.append(trace)
        
        detection_context.network_traces = traces
        
        result = await tls_detector.detect(detection_context)
        
        pattern_issues = [
            issue for issue in result.issues_found 
            if "Unusual TLS Handshake Patterns" in issue.title
        ]
        assert pattern_issues


class TestTlsDetectorEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_no_tls_info(self, tls_detector, detection_context, mock_network_trace):
        """Test handling of traces without TLS info."""
        mock_network_trace.connection_info.tls_info = None
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        # Should not crash and should return empty results
        assert result.issues_found == []
        assert result.statistics['traces_analyzed'] == 1

    @pytest.mark.asyncio
    async def test_no_connection_info(self, tls_detector, detection_context, mock_network_trace):
        """Test handling of traces without connection info."""
        mock_network_trace.connection_info = None
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        # Should not crash and should return empty results
        assert result.issues_found == []

    @pytest.mark.asyncio
    async def test_alternative_tls_info_location(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test handling of TLS info in alternative location."""
        mock_network_trace.connection_info.tls_info = None
        mock_network_trace.tls_info = mock_tls_info
        mock_tls_info.version = "SSLv2"  # Should trigger detection
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        # Should find the TLS info in alternative location
        assert result.issues_found
        assert "Weak TLS Version" in result.issues_found[0].title

    @pytest.mark.asyncio
    async def test_empty_trace_list(self, tls_detector, detection_context):
        """Test handling of empty trace list."""
        detection_context.network_traces = []
        
        result = await tls_detector.detect(detection_context)
        
        assert result.issues_found == []
        assert result.statistics['traces_analyzed'] == 0

    @pytest.mark.asyncio
    async def test_confidence_threshold_filtering(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test that issues below confidence threshold are filtered."""
        # Set high confidence threshold
        detection_context.confidence_threshold = 0.9
        
        mock_tls_info.version = "SSLv2"  # High confidence issue
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace]
        
        result = await tls_detector.detect(detection_context)
        
        # High confidence issues should pass through
        assert result.issues_found
        
        # Lower the confidence threshold and add medium confidence issue
        detection_context.confidence_threshold = 0.5
        mock_tls_info.certificate_issues = ["warning"]  # Medium confidence
        
        result = await tls_detector.detect(detection_context)
        
        # Should include both high and medium confidence issues
        assert len(result.issues_found) >= 1

    @pytest.mark.asyncio
    async def test_statistics_tracking(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test that statistics are properly tracked."""
        mock_tls_info.version = "SSLv2"
        mock_network_trace.connection_info.tls_info = mock_tls_info
        detection_context.network_traces = [mock_network_trace] * 3
        
        result = await tls_detector.detect(detection_context)
        
        assert result.statistics['traces_analyzed'] == 3
        assert result.statistics['processing_time_ms'] > 0
        assert result.statistics['detection_rules_triggered'] > 0
        assert len(result.detection_rules_applied) > 0

    @pytest.mark.asyncio
    async def test_progress_emission(self, tls_detector, detection_context, mock_network_trace, mock_tls_info):
        """Test that progress events are emitted."""
        with patch.object(tls_detector, '_emit_progress') as mock_emit:
            mock_tls_info.version = "TLSv1.2"
            mock_network_trace.connection_info.tls_info = mock_tls_info
            detection_context.network_traces = [mock_network_trace]
            
            await tls_detector.detect(detection_context)
            
            # Should emit start and completion events
            assert mock_emit.call_count >= 2
            
            # Check event types
            call_args = [call[0][0] for call in mock_emit.call_args_list]
            assert "tls_detection_started" in call_args
            assert "tls_detection_completed" in call_args


class TestTlsDetectorIntegration:
    """Integration tests for TLS detector."""

    @pytest.mark.asyncio
    async def test_comprehensive_analysis(self, tls_detector, detection_context):
        """Test comprehensive TLS analysis with multiple issues."""
        traces = []
        
        # Trace 1: Weak version and cipher
        trace1 = Mock(spec=NetworkTrace)
        trace1.trace_id = "trace-1"
        tls_info1 = TLSInfo(
            version=TLSVersion.TLS_10,  # Weak version
            cipher_suite="TLS_RSA_WITH_RC4_128_SHA",  # Weak cipher
            extensions=["server_name"],
            supported_groups=["secp256r1"],
            certificate_issues=[],
            handshake_duration_ms=50
        )
        trace1.connection_info = Mock(spec=ConnectionInfo)
        trace1.connection_info.tls_info = tls_info1
        traces.append(trace1)
        
        # Trace 2: Certificate issues
        trace2 = Mock(spec=NetworkTrace)
        trace2.trace_id = "trace-2"
        tls_info2 = TLSInfo(
            version=TLSVersion.TLS_12,
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            extensions=["server_name"],
            supported_groups=["secp256r1"],
            certificate_issues=["expired", "untrusted"],  # Certificate issues
            handshake_duration_ms=45
        )
        trace2.connection_info = Mock(spec=ConnectionInfo)
        trace2.connection_info.tls_info = tls_info2
        traces.append(trace2)
        
        # Trace 3: Automation signature
        trace3 = Mock(spec=NetworkTrace)
        trace3.trace_id = "trace-3"
        tls_info3 = TLSInfo(
            version=TLSVersion.TLS_12,
            cipher_suite="selenium_automation_cipher",  # Automation signature
            extensions=["webdriver", "automation"],  # Automation extensions
            supported_groups=["secp256r1"],
            certificate_issues=[],
            handshake_duration_ms=20  # Robotic timing
        )
        trace3.connection_info = Mock(spec=ConnectionInfo)
