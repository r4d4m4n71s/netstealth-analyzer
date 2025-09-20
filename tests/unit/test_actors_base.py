"""
Unit tests for the Network Actor base classes and patterns.

Tests the core functionality of the network actor detection system including
pattern matching, actor identification, and behavioral analysis.

Author: NetStealth Analyzer Team
Version: 1.0.0
Python: 3.13+
"""

import pytest
import ipaddress
from datetime import datetime
from unittest.mock import Mock, patch

from src.netstealth_analyzer.actors.base import (
    ActorCategory, AnonymityLevel, ActorIdentification, BehaviorAnalysis,
    HeaderPattern, IPRangePattern, ResponsePattern, PortPattern, NetworkActor
)
from src.netstealth_analyzer.models.enums import RiskLevel, DetectionConfidence
from src.netstealth_analyzer.models.network import NetworkTrace, NetworkHop, HttpTrace, HttpRequest, HttpResponse


class TestActorIdentification:
    """Test ActorIdentification dataclass."""
    
    def test_valid_identification(self):
        """Test creating valid actor identification."""
        identification = ActorIdentification(
            actor_type="test_actor",
            actor_category=ActorCategory.PROXY,
            confidence=0.8,
            patterns_matched=["pattern1", "pattern2"],
            metadata={"key": "value"}
        )
        
        assert identification.actor_type == "test_actor"
        assert identification.actor_category == ActorCategory.PROXY
        assert identification.confidence == 0.8
        assert identification.patterns_matched == ["pattern1", "pattern2"]
        assert identification.metadata == {"key": "value"}
        assert isinstance(identification.timestamp, datetime)
    
    def test_confidence_validation(self):
        """Test confidence score validation."""
        # Valid confidence scores
        ActorIdentification("test", ActorCategory.PROXY, 0.0)
        ActorIdentification("test", ActorCategory.PROXY, 0.5)
        ActorIdentification("test", ActorCategory.PROXY, 1.0)
        
        # Invalid confidence scores
        with pytest.raises(ValueError, match="Confidence must be between 0.0 and 1.0"):
            ActorIdentification("test", ActorCategory.PROXY, -0.1)
        
        with pytest.raises(ValueError, match="Confidence must be between 0.0 and 1.0"):
            ActorIdentification("test", ActorCategory.PROXY, 1.1)
    
    def test_confidence_level_property(self):
        """Test confidence level enum property."""
        low_conf = ActorIdentification("test", ActorCategory.PROXY, 0.3)
        assert low_conf.confidence_level == DetectionConfidence.LOW
        
        high_conf = ActorIdentification("test", ActorCategory.PROXY, 0.8)
        assert high_conf.confidence_level == DetectionConfidence.HIGH
    
    def test_is_high_confidence(self):
        """Test high confidence check."""
        low_conf = ActorIdentification("test", ActorCategory.PROXY, 0.7)
        assert not low_conf.is_high_confidence()
        
        high_conf = ActorIdentification("test", ActorCategory.PROXY, 0.8)
        assert high_conf.is_high_confidence()


class TestBehaviorAnalysis:
    """Test BehaviorAnalysis dataclass."""
    
    def test_valid_behavior_analysis(self):
        """Test creating valid behavior analysis."""
        analysis = BehaviorAnalysis(
            risk_level=RiskLevel.HIGH,
            risk_score=0.7,
            anonymity_level=AnonymityLevel.ANONYMOUS,
            detection_likelihood=0.6,
            performance_impact="Moderate latency",
            characteristics={"type": "datacenter"},
            recommendations=["Use residential proxies"]
        )
        
        assert analysis.risk_level == RiskLevel.HIGH
        assert analysis.risk_score == 0.7
        assert analysis.anonymity_level == AnonymityLevel.ANONYMOUS
        assert analysis.detection_likelihood == 0.6
        assert analysis.performance_impact == "Moderate latency"
        assert analysis.characteristics == {"type": "datacenter"}
        assert analysis.recommendations == ["Use residential proxies"]
    
    def test_score_validation(self):
        """Test risk score and detection likelihood validation."""
        # Valid scores
        BehaviorAnalysis(
            RiskLevel.LOW, 0.0, AnonymityLevel.ELITE, 0.0, "Low impact"
        )
        BehaviorAnalysis(
            RiskLevel.HIGH, 1.0, AnonymityLevel.TRANSPARENT, 1.0, "High impact"
        )
        
        # Invalid risk scores
        with pytest.raises(ValueError, match="Risk score must be between 0.0 and 1.0"):
            BehaviorAnalysis(
                RiskLevel.LOW, -0.1, AnonymityLevel.ELITE, 0.5, "Impact"
            )
        
        with pytest.raises(ValueError, match="Detection likelihood must be between 0.0 and 1.0"):
            BehaviorAnalysis(
                RiskLevel.LOW, 0.5, AnonymityLevel.ELITE, 1.1, "Impact"
            )
    
    def test_get_summary(self):
        """Test behavior analysis summary."""
        analysis = BehaviorAnalysis(
            risk_level=RiskLevel.MEDIUM,
            risk_score=0.5,
            anonymity_level=AnonymityLevel.ANONYMOUS,
            detection_likelihood=0.4,
            performance_impact="Moderate",
            characteristics={"a": 1, "b": 2},
            recommendations=["rec1", "rec2", "rec3"]
        )
        
        summary = analysis.get_summary()
        
        assert summary['risk_level'] == 'medium'
        assert summary['risk_score'] == 0.5
        assert summary['anonymity_level'] == 'anonymous'
        assert summary['detection_likelihood'] == 0.4
        assert summary['performance_impact'] == 'Moderate'
        assert summary['characteristics_count'] == 2
        assert summary['recommendations_count'] == 3


class TestHeaderPattern:
    """Test HeaderPattern class."""
    
    def create_mock_trace_with_headers(self, headers):
        """Create mock trace with specified headers."""
        trace = Mock(spec=NetworkTrace)
        trace.is_http.return_value = True
        trace.http_data = Mock(spec=HttpTrace)
        trace.http_data.request = Mock(spec=HttpRequest)
        trace.http_data.request.headers = headers
        return trace
    
    def test_header_pattern_creation(self):
        """Test creating header patterns."""
        pattern = HeaderPattern("X-Forwarded-For", confidence=0.8, required=True)
        
        assert pattern.header_name == "x-forwarded-for"  # Should be lowercase
        assert pattern.confidence == 0.8
        assert pattern.required is True
        assert pattern.value_pattern is None
        assert not pattern.case_sensitive
    
    def test_header_pattern_with_value(self):
        """Test header pattern with value regex."""
        pattern = HeaderPattern(
            "User-Agent", 
            value_pattern=r"Mozilla.*",
            case_sensitive=True,
            confidence=0.7
        )
        
        assert pattern.header_name == "User-Agent"  # Should preserve case
        assert pattern.value_pattern.pattern == r"Mozilla.*"
        assert pattern.case_sensitive is True
    
    def test_header_matching_simple(self):
        """Test simple header matching."""
        pattern = HeaderPattern("X-Forwarded-For")
        
        # Matching header
        trace = self.create_mock_trace_with_headers([
            {"name": "X-Forwarded-For", "value": "192.168.1.1"}
        ])
        assert pattern.matches(trace) is True
        
        # Non-matching header
        trace = self.create_mock_trace_with_headers([
            {"name": "User-Agent", "value": "Mozilla/5.0"}
        ])
        assert pattern.matches(trace) is False
        
        # No headers
        trace = self.create_mock_trace_with_headers([])
        assert pattern.matches(trace) is False
    
    def test_header_matching_with_value_pattern(self):
        """Test header matching with value pattern."""
        pattern = HeaderPattern("User-Agent", value_pattern=r"Mozilla.*")
        
        # Matching header and value
        trace = self.create_mock_trace_with_headers([
            {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0)"}
        ])
        assert pattern.matches(trace) is True
        
        # Matching header, non-matching value
        trace = self.create_mock_trace_with_headers([
            {"name": "User-Agent", "value": "Chrome/91.0"}
        ])
        assert pattern.matches(trace) is False
    
    def test_header_case_sensitivity(self):
        """Test header case sensitivity."""
        case_sensitive = HeaderPattern("User-Agent", case_sensitive=True)
        case_insensitive = HeaderPattern("User-Agent", case_sensitive=False)
        
        trace = self.create_mock_trace_with_headers([
            {"name": "user-agent", "value": "test"}
        ])
        
        assert case_sensitive.matches(trace) is False
        assert case_insensitive.matches(trace) is True
    
    def test_header_non_http_trace(self):
        """Test header pattern with non-HTTP trace."""
        pattern = HeaderPattern("X-Forwarded-For")
        
        trace = Mock(spec=NetworkTrace)
        trace.is_http.return_value = False
        
        assert pattern.matches(trace) is False
    
    def test_get_match_info(self):
        """Test getting header pattern match information."""
        pattern = HeaderPattern(
            "X-Forwarded-For", 
            value_pattern=r"\d+\.\d+\.\d+\.\d+",
            confidence=0.9,
            description="Proxy header"
        )
        
        trace = self.create_mock_trace_with_headers([
            {"name": "X-Forwarded-For", "value": "192.168.1.1"}
        ])
        
        info = pattern.get_match_info(trace)
        
        assert info['pattern_type'] == 'HeaderPattern'
        assert info['confidence'] == 0.9
        assert info['description'] == "Proxy header"
        assert info['header_name'] == "x-forwarded-for"
        assert info['value_pattern'] == r"\d+\.\d+\.\d+\.\d+"
        assert info['case_sensitive'] is False
        assert info['matches'] is True


class TestIPRangePattern:
    """Test IPRangePattern class."""
    
    def create_mock_trace_with_hops(self, hops_data):
        """Create mock trace with specified hop data."""
        trace = Mock(spec=NetworkTrace)
        hops = []
        
        for hop_data in hops_data:
            hop = Mock(spec=NetworkHop)
            hop.incoming_ip = hop_data.get('incoming_ip', '0.0.0.0')
            hop.outgoing_ip = hop_data.get('outgoing_ip', '0.0.0.0')
            hops.append(hop)
        
        trace.hops = hops
        return trace
    
    def test_ip_range_pattern_creation(self):
        """Test creating IP range patterns."""
        pattern = IPRangePattern(
            ["192.168.1.0/24", "10.0.0.0/8"],
            confidence=0.7,
            check_source=True,
            check_destination=False
        )
        
        assert len(pattern.ip_networks) == 2
        assert ipaddress.ip_network("192.168.1.0/24") in pattern.ip_networks
        assert ipaddress.ip_network("10.0.0.0/8") in pattern.ip_networks
        assert pattern.check_source is True
        assert pattern.check_destination is False
    
    def test_invalid_ip_range(self):
        """Test invalid IP range handling."""
        with pytest.raises(ValueError, match="Invalid IP range"):
            IPRangePattern(["invalid.range"])
    
    def test_ip_matching_source(self):
        """Test IP matching for source IPs."""
        pattern = IPRangePattern(
            ["192.168.1.0/24"],
            check_source=True,
            check_destination=False
        )
        
        # Matching source IP
        trace = self.create_mock_trace_with_hops([
            {"incoming_ip": "192.168.1.100", "outgoing_ip": "8.8.8.8"}
        ])
        assert pattern.matches(trace) is True
        
        # Non-matching source IP
        trace = self.create_mock_trace_with_hops([
            {"incoming_ip": "8.8.8.8", "outgoing_ip": "192.168.1.100"}
        ])
        assert pattern.matches(trace) is False
    
    def test_ip_matching_destination(self):
        """Test IP matching for destination IPs."""
        pattern = IPRangePattern(
            ["192.168.1.0/24"],
            check_source=False,
            check_destination=True
        )
        
        # Matching destination IP
        trace = self.create_mock_trace_with_hops([
            {"incoming_ip": "8.8.8.8", "outgoing_ip": "192.168.1.100"}
        ])
        assert pattern.matches(trace) is True
        
        # Non-matching destination IP
        trace = self.create_mock_trace_with_hops([
            {"incoming_ip": "192.168.1.100", "outgoing_ip": "8.8.8.8"}
        ])
        assert pattern.matches(trace) is False
    
    def test_ip_matching_multiple_hops(self):
        """Test IP matching across multiple hops."""
        pattern = IPRangePattern(["10.0.0.0/8"])
        
        trace = self.create_mock_trace_with_hops([
            {"incoming_ip": "8.8.8.8", "outgoing_ip": "1.1.1.1"},
            {"incoming_ip": "10.0.0.1", "outgoing_ip": "8.8.8.8"}  # Match in second hop
        ])
        
        assert pattern.matches(trace) is True
    
    def test_invalid_ip_addresses(self):
        """Test handling of invalid IP addresses."""
        pattern = IPRangePattern(["192.168.1.0/24"])
        
        trace = self.create_mock_trace_with_hops([
            {"incoming_ip": "invalid.ip", "outgoing_ip": "also.invalid"}
        ])
        
        # Should not raise exception, should return False
        assert pattern.matches(trace) is False


class TestResponsePattern:
    """Test ResponsePattern class."""
    
    def create_mock_trace_with_response(self, response_body):
        """Create mock trace with specified response body."""
        trace = Mock(spec=NetworkTrace)
        trace.is_http.return_value = True
        trace.http_data = Mock(spec=HttpTrace)
        trace.http_data.response = Mock(spec=HttpResponse)
        trace.http_data.response.body = response_body
        return trace
    
    def test_response_pattern_creation(self):
        """Test creating response patterns."""
        pattern = ResponsePattern(
            r"proxy.*detected",
            case_sensitive=True,
            confidence=0.8
        )
        
        assert pattern.pattern.pattern == r"proxy.*detected"
        assert pattern.case_sensitive is True
        assert pattern.confidence == 0.8
    
    def test_response_matching_case_insensitive(self):
        """Test case-insensitive response matching."""
        pattern = ResponsePattern(r"proxy.*detected", case_sensitive=False)
        
        # Matching response (different case)
        trace = self.create_mock_trace_with_response("PROXY WAS DETECTED")
        assert pattern.matches(trace) is True
        
        # Non-matching response
        trace = self.create_mock_trace_with_response("No issues found")
        assert pattern.matches(trace) is False
    
    def test_response_matching_case_sensitive(self):
        """Test case-sensitive response matching."""
        pattern = ResponsePattern(r"Proxy.*detected", case_sensitive=True)
        
        # Matching response (exact case)
        trace = self.create_mock_trace_with_response("Proxy was detected")
        assert pattern.matches(trace) is True
        
        # Non-matching response (wrong case)
        trace = self.create_mock_trace_with_response("proxy was detected")
        assert pattern.matches(trace) is False
    
    def test_response_non_http_trace(self):
        """Test response pattern with non-HTTP trace."""
        pattern = ResponsePattern(r"test")
        
        trace = Mock(spec=NetworkTrace)
        trace.is_http.return_value = False
        
        assert pattern.matches(trace) is False
    
    def test_response_no_body(self):
        """Test response pattern with no response body."""
        pattern = ResponsePattern(r"test")
        
        trace = Mock(spec=NetworkTrace)
        trace.is_http.return_value = True
        trace.http_data = Mock(spec=HttpTrace)
        trace.http_data.response = Mock(spec=HttpResponse)
        trace.http_data.response.body = None
        
        assert pattern.matches(trace) is False


class TestPortPattern:
    """Test PortPattern class."""
    
    def create_mock_trace_with_ports(self, hops_data):
        """Create mock trace with specified port data."""
        trace = Mock(spec=NetworkTrace)
        hops = []
        
        for hop_data in hops_data:
            hop = Mock(spec=NetworkHop)
            if hop_data:
                hop.connection_info = Mock()
                hop.connection_info.source_port = hop_data.get('source_port', 80)
                hop.connection_info.destination_port = hop_data.get('destination_port', 443)
            else:
                hop.connection_info = None
            hops.append(hop)
        
        trace.hops = hops
        return trace
    
    def test_port_pattern_creation(self):
        """Test creating port patterns."""
        pattern = PortPattern(
            [80, 443, 8080],
            check_source=True,
            check_destination=False,
            confidence=0.6
        )
        
        assert pattern.ports == {80, 443, 8080}
        assert pattern.check_source is True
        assert pattern.check_destination is False
        assert pattern.confidence == 0.6
    
    def test_port_matching_destination(self):
        """Test port matching for destination ports."""
        pattern = PortPattern([8080, 3128], check_destination=True, check_source=False)
        
        # Matching destination port
        trace = self.create_mock_trace_with_ports([
            {"source_port": 12345, "destination_port": 8080}
        ])
        assert pattern.matches(trace) is True
        
        # Non-matching destination port
        trace = self.create_mock_trace_with_ports([
            {"source_port": 8080, "destination_port": 443}
        ])
        assert pattern.matches(trace) is False
    
    def test_port_matching_source(self):
        """Test port matching for source ports."""
        pattern = PortPattern([8080, 3128], check_source=True, check_destination=False)
        
        # Matching source port
        trace = self.create_mock_trace_with_ports([
            {"source_port": 8080, "destination_port": 443}
        ])
        assert pattern.matches(trace) is True
        
        # Non-matching source port
        trace = self.create_mock_trace_with_ports([
            {"source_port": 12345, "destination_port": 8080}
        ])
        assert pattern.matches(trace) is False
    
    def test_port_no_connection_info(self):
        """Test port matching with no connection info."""
        pattern = PortPattern([8080])
        
        trace = self.create_mock_trace_with_ports([None])  # No connection info
        
        assert pattern.matches(trace) is False


class TestNetworkActor:
    """Test NetworkActor base class."""
    
    class MockActor(NetworkActor):
        """Mock actor for testing."""
        
        @property
        def actor_type(self) -> str:
            return "mock_actor"
        
        @property
        def actor_category(self) -> ActorCategory:
            return ActorCategory.PROXY
        
        @property
        def patterns(self):
            return [
                HeaderPattern("X-Test-Header", confidence=0.8, required=True),
                IPRangePattern(["192.168.1.0/24"], confidence=0.6)
            ]
        
        def analyze_behavior(self, trace, identification):
            return BehaviorAnalysis(
                risk_level=RiskLevel.LOW,
                risk_score=0.3,
                anonymity_level=AnonymityLevel.ANONYMOUS,
                detection_likelihood=0.2,
                performance_impact="Low impact"
            )
    
    def test_actor_initialization(self):
        """Test actor initialization."""
        actor = self.MockActor()
        
        assert actor.actor_type == "mock_actor"
        assert actor.actor_category == ActorCategory.PROXY
        assert len(actor.patterns) == 2
        assert not actor._compiled_patterns
    
    def test_pattern_compilation(self):
        """Test pattern compilation."""
        actor = self.MockActor()
        
        # Patterns should be compiled on first access
        actor._ensure_patterns_compiled()
        
        assert actor._compiled_patterns is True
        assert len(actor._patterns) == 2
    
    def test_successful_identification(self):
        """Test successful actor identification."""
        actor = self.MockActor()
        
        # Create trace that matches required pattern
        trace = Mock(spec=NetworkTrace)
        trace.is_http.return_value = True
        trace.http_data = Mock(spec=HttpTrace)
        trace.http_data.request = Mock(spec=HttpRequest)
        trace.http_data.request.headers = [
            {"name": "X-Test-Header", "value": "test"}
        ]
        trace.hops = []
        
        identification = actor.identify(trace)
        
        assert identification is not None
        assert identification.actor_type == "mock_actor"
        assert identification.actor_category == ActorCategory.PROXY
        assert identification.confidence > 0
        assert "HeaderPattern" in identification.patterns_matched
    
    def test_failed_identification_missing_required(self):
        """Test failed identification when required pattern is missing."""
        actor = self.MockActor()
        
        # Create trace that doesn't match required pattern
        trace = Mock(spec=NetworkTrace)
        trace.is_http.return_value = True
        trace.http_data = Mock(spec=HttpTrace)
        trace.http_data.request = Mock(spec=HttpRequest)
        trace.http_data.request.headers = []  # No headers
        trace.hops = [Mock(spec=NetworkHop)]
        trace.hops[0].incoming_ip = "192.168.1.100"  # Matches IP pattern
        trace.hops[0].outgoing_ip = "8.8.8.8"
        
        identification = actor.identify(trace)
        
        # Should fail because required header pattern is not matched
        assert identification is None
    
    def test_confidence_calculation(self):
        """Test confidence calculation with multiple patterns."""
        actor = self.MockActor()
        
        # Create trace that matches both patterns
        trace = Mock(spec=NetworkTrace)
        trace.is_http.return_value = True
        trace.http_data = Mock(spec=HttpTrace)
        trace.http_data.request = Mock(spec=HttpRequest)
        trace.http_data.request.headers = [
            {"name": "X-Test-Header", "value": "test"}
        ]
        trace.hops = [Mock(spec=NetworkHop)]
        trace.hops[0].incoming_ip = "192.168.1.100"
        trace.hops[0].outgoing_ip = "8.8.8.8"
        
        identification = actor.identify(trace)
        
        assert identification is not None
        # Should have higher confidence due to multiple pattern matches
        assert identification.confidence > 0.6
        assert len(identification.patterns_matched) == 2
    
    def test_get_actor_info(self):
        """Test getting actor information."""
        actor = self.MockActor()
        
        info = actor.get_actor_info()
        
        assert info['actor_type'] == "mock_actor"
        assert info['actor_category'] == "proxy"
        assert info['patterns_count'] == 2
        assert info['required_patterns'] == 1
        assert 'description' in info
    
    def test_string_representations(self):
        """Test string representations of actor."""
        actor = self.MockActor()
        
        str_repr = str(actor)
        assert "MockActor" in str_repr
        assert "mock_actor" in str_repr
        assert "proxy" in str_repr
        
        repr_str = repr(actor)
        assert "MockActor" in repr_str
        assert "mock_actor" in repr_str
        assert "proxy" in repr_str
        assert "patterns=2" in repr_str


if __name__ == "__main__":
    pytest.main([__file__])
