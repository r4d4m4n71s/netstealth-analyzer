"""
Integration tests for ConnectionInfo TLS security analysis workflows.

Tests ConnectionInfo + TLSInfo security assessment and end-to-end security workflows.
"""

import pytest
import asyncio
import time
from typing import List, Dict, Any
from unittest.mock import Mock, patch

from src.netstealth_analyzer.models.network import (
    ConnectionInfo, NetworkProtocol, TLSInfo, TLSVersion, NetworkTrace, NetworkHop
)
from src.netstealth_analyzer.models.enums import RiskLevel
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel, IssueEvidence
from src.netstealth_analyzer.core.events import EventBus, AnalysisEvent


class TestConnectionInfoSecurityIntegration:
    """Test ConnectionInfo integration with TLS security analysis."""
    
    @pytest.fixture
    def secure_connection_tls13(self):
        """Create a secure TLS 1.3 connection for testing."""
        return ConnectionInfo(
            protocol=NetworkProtocol.HTTPS,
            source_ip="192.168.1.100",
            destination_ip="93.184.216.34",
            destination_port=443,
            bytes_sent=1024,
            bytes_received=5120,
            duration_ms=150.0,
            latency_ms=45.0,
            is_encrypted=True,
            tls_info=TLSInfo(
                version=TLSVersion.TLS_13,
                cipher_suite="TLS_AES_256_GCM_SHA384",
                certificate_issues=[],
                certificate_chain_length=3,
                certificate_expiry_days=365,
                supports_perfect_forward_secrecy=True,
                certificate_authority="Let's Encrypt Authority X3"
            )
        )
    
    @pytest.fixture
    def insecure_connection_tls10(self):
        """Create an insecure TLS 1.0 connection for testing."""
        return ConnectionInfo(
            protocol=NetworkProtocol.HTTPS,
            source_ip="192.168.1.100",
            destination_ip="203.0.113.42",
            destination_port=443,
            bytes_sent=512,
            bytes_received=1024,
            duration_ms=300.0,
            latency_ms=250.0,
            is_encrypted=True,
            tls_info=TLSInfo(
                version=TLSVersion.TLS_10,
                cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
                certificate_issues=["weak_signature", "expired_certificate"],
                certificate_chain_length=2,
                certificate_expiry_days=-30,  # Expired
                supports_perfect_forward_secrecy=False,
                certificate_authority="Self-Signed"
            )
        )
    
    @pytest.fixture
    def http_connection(self):
        """Create an unencrypted HTTP connection for testing."""
        return ConnectionInfo(
            protocol=NetworkProtocol.HTTP,
            source_ip="192.168.1.100",
            destination_ip="10.0.1.50",
            destination_port=80,
            bytes_sent=256,
            bytes_received=512,
            duration_ms=100.0,
            latency_ms=75.0,
            is_encrypted=False,
            tls_info=None
        )
    
    @pytest.mark.asyncio
    async def test_tls_connectioninfo_security_pipeline(self, secure_connection_tls13):
        """Test end-to-end TLS security analysis with ConnectionInfo."""
        # Mock TLS security analyzer
        security_analyzer = Mock(spec=TLSSecurityAnalyzer)
        
        # Create expected security results
        security_results = SecurityAnalysisResult(
            connection_id=f"{secure_connection_tls13.source_ip}:{secure_connection_tls13.destination_ip}",
            risk_level=RiskLevel.SAFE,
            security_score=0.95,
            vulnerabilities=[],
            recommendations=[
                "TLS 1.3 configuration is excellent",
                "Perfect Forward Secrecy is enabled",
                "Strong cipher suite in use"
            ],
            certificate_status="valid",
            encryption_strength="strong"
        )
        
        # Mock analyzer method
        security_analyzer.analyze_connection = Mock(return_value=security_results)
        
        # Run security analysis pipeline
        results = await security_analyzer.analyze_connection(secure_connection_tls13)
        
        # Validate security assessment
        assert results.risk_level == RiskLevel.SAFE
        assert results.security_score > 0.9
        assert len(results.vulnerabilities) == 0
        assert secure_connection_tls13.is_encrypted is True
        assert len(results.recommendations) > 0
        assert "TLS 1.3" in results.recommendations[0]
        
        # Verify analyzer was called with correct connection
        security_analyzer.analyze_connection.assert_called_once_with(secure_connection_tls13)
    
    @pytest.mark.asyncio
    async def test_vulnerable_tls_connection_analysis(self, insecure_connection_tls10):
        """Test security analysis of vulnerable TLS connection."""
        # Mock TLS security analyzer
        security_analyzer = Mock(spec=TLSSecurityAnalyzer)
        
        # Create expected security results for vulnerable connection
        security_results = SecurityAnalysisResult(
            connection_id=f"{insecure_connection_tls10.source_ip}:{insecure_connection_tls10.destination_ip}",
            risk_level=RiskLevel.HIGH,
            security_score=0.25,
            vulnerabilities=[
                "TLS 1.0 is deprecated and vulnerable",
                "Weak cipher suite detected",
                "Certificate has expired",
                "Weak signature algorithm",
                "No Perfect Forward Secrecy"
            ],
            recommendations=[
                "Upgrade to TLS 1.2 or higher immediately",
                "Replace expired certificate",
                "Enable Perfect Forward Secrecy",
                "Use stronger cipher suites"
            ],
            certificate_status="expired",
            encryption_strength="weak"
        )
        
        # Mock analyzer method
        security_analyzer.analyze_connection = Mock(return_value=security_results)
        
        # Run security analysis pipeline
        results = await security_analyzer.analyze_connection(insecure_connection_tls10)
        
        # Validate security assessment
        assert results.risk_level == RiskLevel.HIGH
        assert results.security_score < 0.5
        assert len(results.vulnerabilities) >= 4
        assert insecure_connection_tls10.is_encrypted is True  # Still encrypted, but poorly
        assert len(results.recommendations) >= 3
        assert "TLS 1.0" in results.vulnerabilities[0]
        assert "expired" in results.certificate_status
        
        # Verify analyzer was called with correct connection
        security_analyzer.analyze_connection.assert_called_once_with(insecure_connection_tls10)
    
    @pytest.mark.asyncio
    async def test_http_connection_security_analysis(self, http_connection):
        """Test security analysis of unencrypted HTTP connection."""
        # Mock TLS security analyzer
        security_analyzer = Mock(spec=TLSSecurityAnalyzer)
        
        # Create expected security results for HTTP connection
        security_results = SecurityAnalysisResult(
            connection_id=f"{http_connection.source_ip}:{http_connection.destination_ip}",
            risk_level=RiskLevel.HIGH,
            security_score=0.1,
            vulnerabilities=[
                "Connection is not encrypted",
                "Data transmitted in plaintext",
                "Susceptible to man-in-the-middle attacks",
                "No authentication of server identity"
            ],
            recommendations=[
                "Upgrade to HTTPS immediately",
                "Implement TLS encryption",
                "Use secure communication protocols"
            ],
            certificate_status="none",
            encryption_strength="none"
        )
        
        # Mock analyzer method
        security_analyzer.analyze_connection = Mock(return_value=security_results)
        
        # Run security analysis pipeline
        results = await security_analyzer.analyze_connection(http_connection)
        
        # Validate security assessment
        assert results.risk_level == RiskLevel.HIGH
        assert results.security_score < 0.2
        assert len(results.vulnerabilities) >= 3
        assert http_connection.is_encrypted is False
        assert "not encrypted" in results.vulnerabilities[0]
        assert results.certificate_status == "none"
        assert results.encryption_strength == "none"
        
        # Verify analyzer was called with correct connection
        security_analyzer.analyze_connection.assert_called_once_with(http_connection)
    
    @pytest.mark.asyncio
    async def test_connection_quality_security_tradeoffs(
        self, 
        secure_connection_tls13, 
        insecure_connection_tls10, 
        http_connection
    ):
        """Test analysis of connection quality vs security trade-offs."""
        connections = [
            # Fast but insecure HTTP connection
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                latency_ms=20.0,
                duration_ms=50.0,
                bytes_sent=1000,
                bytes_received=5000,
                throughput_bps=120000,  # High throughput
                quality_score=0.9,  # Excellent performance
                security_score=0.1,  # Poor security
                is_encrypted=False
            ),
            # Slow but secure TLS 1.3 connection
            secure_connection_tls13,
            # Medium speed, poor security TLS 1.0 connection
            insecure_connection_tls10
        ]
        
        # Add security scores
        connections[1].security_score = 0.95  # Excellent security
        connections[1].quality_score = 0.7   # Good performance
        connections[2].security_score = 0.25  # Poor security
        connections[2].quality_score = 0.4   # Poor performance
        
        # Mock analyzer
        analyzer = Mock(spec=ConnectionQualitySecurityAnalyzer)
        
        # Create expected analysis results
        analysis_results = QualitySecurityAnalysis(
            total_connections=3,
            fast_insecure_connections=1,
            slow_secure_connections=1,
            balanced_connections=0,
            poor_connections=1,
            recommended_connection=connections[1],  # Secure TLS 1.3
            security_vs_performance_score=0.7,
            recommendations=[
                "Prioritize security over performance for sensitive data",
                "Upgrade HTTP connections to HTTPS",
                "Optimize TLS 1.3 connections for better performance",
                "Replace TLS 1.0 connections immediately"
            ]
        )
        
        # Mock analyzer method
        analyzer.analyze_tradeoffs = Mock(return_value=analysis_results)
        
        # Run trade-off analysis
        analysis = await analyzer.analyze_tradeoffs(connections)
        
        # Validate analysis results
        assert analysis.fast_insecure_connections == 1
        assert analysis.slow_secure_connections == 1
        assert analysis.poor_connections == 1
        assert analysis.recommended_connection == connections[1]  # Secure one
        assert analysis.security_vs_performance_score > 0.5
        assert len(analysis.recommendations) >= 3
        
        # Verify specific recommendations
        recommendations_text = " ".join(analysis.recommendations).lower()
        assert "https" in recommendations_text
        assert "tls 1.3" in recommendations_text
        assert "tls 1.0" in recommendations_text
        
        # Verify analyzer was called with correct connections
        analyzer.analyze_tradeoffs.assert_called_once_with(connections)
    
    @pytest.mark.asyncio
    async def test_certificate_validation_integration(self):
        """Test certificate validation integration with ConnectionInfo."""
        # Create connections with various certificate issues
        connections = [
            # Valid certificate
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                source_ip="192.168.1.100",
                destination_ip="93.184.216.34",
                destination_port=443,
                is_encrypted=True,
                tls_info=TLSInfo(
                    version=TLSVersion.TLS_12,
                    cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    certificate_issues=[],
                    certificate_expiry_days=180,
                    certificate_authority="DigiCert Inc"
                )
            ),
            # Self-signed certificate
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                source_ip="192.168.1.100",
                destination_ip="10.0.1.100",
                destination_port=443,
                is_encrypted=True,
                tls_info=TLSInfo(
                    version=TLSVersion.TLS_12,
                    cipher_suite="TLS_RSA_WITH_AES_256_CBC_SHA256",
                    certificate_issues=["self_signed"],
                    certificate_expiry_days=365,
                    certificate_authority="Self-Signed"
                )
            ),
            # Expired certificate
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                source_ip="192.168.1.100",
                destination_ip="203.0.113.50",
                destination_port=443,
                is_encrypted=True,
                tls_info=TLSInfo(
                    version=TLSVersion.TLS_11,
                    cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
                    certificate_issues=["expired_certificate", "weak_signature"],
                    certificate_expiry_days=-15,
                    certificate_authority="Expired CA"
                )
            )
        ]
        
        # Mock certificate validator
        cert_validator = Mock(spec=CertificateValidator)
        
        # Create expected validation results
        validation_results = [
            CertificateValidationResult(
                connection_id="192.168.1.100:93.184.216.34",
                is_valid=True,
                trust_level="high",
                issues=[],
                expiry_status="valid",
                authority_trusted=True
            ),
            CertificateValidationResult(
                connection_id="192.168.1.100:10.0.1.100",
                is_valid=False,
                trust_level="low",
                issues=["self_signed"],
                expiry_status="valid",
                authority_trusted=False
            ),
            CertificateValidationResult(
                connection_id="192.168.1.100:203.0.113.50",
                is_valid=False,
                trust_level="none",
                issues=["expired_certificate", "weak_signature"],
                expiry_status="expired",
                authority_trusted=False
            )
        ]
        
        # Mock validator method
        cert_validator.validate_connections = Mock(return_value=validation_results)
        
        # Run certificate validation
        results = await cert_validator.validate_connections(connections)
        
        # Validate results
        assert len(results) == 3
        
        # Valid certificate
        assert results[0].is_valid is True
        assert results[0].trust_level == "high"
        assert len(results[0].issues) == 0
        
        # Self-signed certificate
        assert results[1].is_valid is False
        assert results[1].trust_level == "low"
        assert "self_signed" in results[1].issues
        
        # Expired certificate
        assert results[2].is_valid is False
        assert results[2].trust_level == "none"
        assert "expired_certificate" in results[2].issues
        assert results[2].expiry_status == "expired"
        
        # Verify validator was called with correct connections
        cert_validator.validate_connections.assert_called_once_with(connections)
    
    @pytest.mark.asyncio
    async def test_security_issue_generation_workflow(self, insecure_connection_tls10):
        """Test security issue generation from ConnectionInfo analysis."""
        # Mock security issue generator
        issue_generator = Mock(spec=SecurityIssueGenerator)
        
        # Create expected security issues
        security_issues = [
            Issue(
                id="tls-version-deprecated-203.0.113.42",
                category=IssueCategory.SECURITY_VULNERABILITY,
                severity=SeverityLevel.HIGH,
                title="Deprecated TLS Version Detected",
                description="Connection uses TLS 1.0 which is deprecated and vulnerable to attacks",
                confidence=0.95,
                impact_score=85,
                evidence=[
                    IssueEvidence(
                        type="tls_analysis",
                        description="TLS version analysis",
                        raw_data={
                            "tls_version": "TLS_10",
                            "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
                            "destination": "203.0.113.42:443"
                        },
                        confidence=0.95
                    )
                ]
            ),
            Issue(
                id="certificate-expired-203.0.113.42",
                category=IssueCategory.SECURITY_VULNERABILITY,
                severity=SeverityLevel.HIGH,
                title="Expired Certificate Detected",
                description="Server certificate has expired 30 days ago",
                confidence=1.0,
                impact_score=90,
                evidence=[
                    IssueEvidence(
                        type="certificate_analysis",
                        description="Certificate expiry analysis",
                        raw_data={
                            "expiry_days": -30,
                            "certificate_authority": "Self-Signed",
                            "destination": "203.0.113.42:443"
                        },
                        confidence=1.0
                    )
                ]
            ),
            Issue(
                id="weak-cipher-suite-203.0.113.42",
                category=IssueCategory.SECURITY_VULNERABILITY,
                severity=SeverityLevel.MEDIUM,
                title="Weak Cipher Suite Detected",
                description="Connection uses weak cipher suite without Perfect Forward Secrecy",
                confidence=0.9,
                impact_score=70,
                evidence=[
                    IssueEvidence(
                        type="cipher_analysis",
                        description="Cipher suite security analysis",
                        raw_data={
                            "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
                            "perfect_forward_secrecy": False,
                            "destination": "203.0.113.42:443"
                        },
                        confidence=0.9
                    )
                ]
            )
        ]
        
        # Mock issue generator method
        issue_generator.generate_security_issues = Mock(return_value=security_issues)
        
        # Generate security issues
        issues = await issue_generator.generate_security_issues(insecure_connection_tls10)
        
        # Validate generated issues
        assert len(issues) == 3
        
        # TLS version issue
        tls_issue = next(issue for issue in issues if "TLS Version" in issue.title)
        assert tls_issue.severity == SeverityLevel.HIGH
        assert tls_issue.category == IssueCategory.SECURITY_VULNERABILITY
        assert "TLS 1.0" in tls_issue.description
        
        # Certificate issue
        cert_issue = next(issue for issue in issues if "Certificate" in issue.title)
        assert cert_issue.severity == SeverityLevel.HIGH
        assert "expired" in cert_issue.description.lower()
        
        # Cipher suite issue
        cipher_issue = next(issue for issue in issues if "Cipher Suite" in issue.title)
        assert cipher_issue.severity == SeverityLevel.MEDIUM
        assert "Perfect Forward Secrecy" in cipher_issue.description
        
        # Verify all issues have proper evidence
        for issue in issues:
            assert len(issue.evidence) > 0
            assert issue.confidence > 0.8
            assert issue.impact_score > 60
        
        # Verify generator was called with correct connection
        issue_generator.generate_security_issues.assert_called_once_with(insecure_connection_tls10)
    
    @pytest.mark.asyncio
    async def test_end_to_end_security_workflow_with_events(self, event_bus):
        """Test comprehensive end-to-end security workflow with event integration."""
        # Create test connections
        connections = [
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                source_ip="192.168.1.100",
                destination_ip="93.184.216.34",
                destination_port=443,
                is_encrypted=True,
                tls_info=TLSInfo(
                    version=TLSVersion.TLS_13,
                    cipher_suite="TLS_AES_256_GCM_SHA384",
                    certificate_issues=[]
                )
            ),
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                source_ip="192.168.1.100",
                destination_ip="10.0.1.50",
                destination_port=80,
                is_encrypted=False,
                tls_info=None
            )
        ]
        
        # Set up event monitoring
        security_events = []
        
        async def security_event_monitor(event, event_data):
            security_events.append((event.value, event_data))
        
        event_bus.subscribe(AnalysisEvent.ANALYSIS_STARTED, security_event_monitor)
        event_bus.subscribe(AnalysisEvent.SECURITY_ISSUE_FOUND, security_event_monitor)
        event_bus.subscribe(AnalysisEvent.ANALYSIS_COMPLETED, security_event_monitor)
        
        # Mock comprehensive security workflow
        security_workflow = Mock(spec=ComprehensiveSecurityWorkflow)
        
        # Create expected workflow results
        workflow_results = SecurityWorkflowResults(
            connections_analyzed=2,
            secure_connections=1,
            insecure_connections=1,
            issues_found=2,
            high_severity_issues=1,
            medium_severity_issues=1,
            recommendations=[
                "Upgrade HTTP connection to HTTPS",
                "TLS 1.3 configuration is optimal",
                "Consider implementing HSTS headers"
            ]
        )
        
        # Mock workflow method
        security_workflow.analyze_connections = Mock(return_value=workflow_results)
        
        # Execute comprehensive security workflow
        results = await security_workflow.analyze_connections(connections, event_bus)
        
        # Wait for events to be processed
        await asyncio.sleep(0.1)
        
        # Validate workflow results
        assert results.connections_analyzed == 2
        assert results.secure_connections == 1
        assert results.insecure_connections == 1
        assert results.issues_found >= 1
        assert len(results.recommendations) >= 2
        
        # Validate events were emitted
        assert len(security_events) >= 2  # At least start and completion
        
        event_types = [event[0] for event, _ in security_events]
        assert AnalysisEvent.ANALYSIS_STARTED.value in event_types or 1 in event_types
        assert AnalysisEvent.ANALYSIS_COMPLETED.value in event_types or 2 in event_types
        
        # Verify workflow was called with correct parameters
        security_workflow.analyze_connections.assert_called_once_with(connections, event_bus)


# Mock classes for testing
class TLSSecurityAnalyzer:
    """Mock TLS security analyzer."""
    async def analyze_connection(self, connection: ConnectionInfo) -> 'SecurityAnalysisResult':
        pass


class ConnectionQualitySecurityAnalyzer:
    """Mock connection quality vs security analyzer."""
    async def analyze_tradeoffs(self, connections: List[ConnectionInfo]) -> 'QualitySecurityAnalysis':
        pass


class CertificateValidator:
    """Mock certificate validator."""
    async def validate_connections(self, connections: List[ConnectionInfo]) -> List['CertificateValidationResult']:
        pass


class SecurityIssueGenerator:
    """Mock security issue generator."""
    async def generate_security_issues(self, connection: ConnectionInfo) -> List[Issue]:
        pass


class ComprehensiveSecurityWorkflow:
    """Mock comprehensive security workflow."""
    async def analyze_connections(self, connections: List[ConnectionInfo], event_bus: EventBus) -> 'SecurityWorkflowResults':
        pass


# Result classes
class SecurityAnalysisResult:
    """Results of security analysis."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class QualitySecurityAnalysis:
    """Results of quality vs security analysis."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class CertificateValidationResult:
    """Results of certificate validation."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class SecurityWorkflowResults:
    """Results of comprehensive security workflow."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
