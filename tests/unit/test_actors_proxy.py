"""
Unit tests for the ProxyActor implementation.

Tests the proxy detection and behavioral analysis functionality
of the network actor system.

Author: NetStealth Analyzer Team
Version: 1.0.0
Python: 3.13+
"""

import re
import pytest
from unittest.mock import Mock, patch

from src.netstealth_analyzer.actors.proxy import ProxyActor
from src.netstealth_analyzer.actors.base import (
    ActorCategory, AnonymityLevel, ActorIdentification, BehaviorAnalysis
)
from src.netstealth_analyzer.models.enums import RiskLevel, DetectionConfidence
from src.netstealth_analyzer.models.network import (
    NetworkTrace, NetworkHop, HttpTrace, HttpRequest, HttpResponse, 
    GeographicInfo, ConnectionInfo, TimingInfo
)


class TestProxyActor:
    """Test ProxyActor class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.proxy_actor = ProxyActor()
    
    def create_mock_trace_with_headers(self, headers, response_body=None, status_code=200):
        """Create mock trace with specified headers and response."""
        trace = Mock(spec=NetworkTrace)
        trace.is_http.return_value = True
        trace.http_data = Mock(spec=HttpTrace)
        
        # Request setup
        trace.http_data.request = Mock(spec=HttpRequest)
        trace.http_data.request.headers = headers
        trace.http_data.request.url = "https://example.com/test"
        
        # Response setup
        trace.http_data.response = Mock(spec=HttpResponse)
        trace.http_data.response.status_code = status_code
        trace.http_data.response.body = response_body
        trace.http_data.response.headers = []
        
        # Timing setup - ensure all timing attributes are available
        timing_mock = Mock(spec=TimingInfo)
        timing_mock.total_time = 1000  # 1 second
        timing_mock.dns_lookup = 50
        timing_mock.tcp_connect = 100
        timing_mock.ssl_handshake = 150
        timing_mock.request_sent = 200
        timing_mock.first_byte = 800
        timing_mock.content_download = 200
        trace.http_data.timing = timing_mock
        
        # Hops setup
        trace.hops = []
        
        return trace
    
    def create_mock_trace_with_hops(self, hops_data, headers=None):
        """Create mock trace with specified hop data."""
        trace = Mock(spec=NetworkTrace)
        trace.is_http.return_value = True
        trace.http_data = Mock(spec=HttpTrace)
        
        # Request setup
        trace.http_data.request = Mock(spec=HttpRequest)
        trace.http_data.request.headers = headers or []
        trace.http_data.request.url = "https://example.com/test"
        
        # Response setup
        trace.http_data.response = Mock(spec=HttpResponse)
        trace.http_data.response.status_code = 200
        trace.http_data.response.body = ""
        trace.http_data.response.headers = []
        
        # Timing setup - ensure all timing attributes are available
        timing_mock = Mock(spec=TimingInfo)
        timing_mock.total_time = 1000  # 1 second
        timing_mock.dns_lookup = 50
        timing_mock.tcp_connect = 100
        timing_mock.ssl_handshake = 150
        timing_mock.request_sent = 200
        timing_mock.first_byte = 800
        timing_mock.content_download = 200
        trace.http_data.timing = timing_mock
        
        # Hops setup
        hops = []
        for hop_data in hops_data:
            hop = Mock(spec=NetworkHop)
            hop.incoming_ip = hop_data.get('incoming_ip', '0.0.0.0')
            hop.outgoing_ip = hop_data.get('outgoing_ip', '0.0.0.0')
            
            # Geographic info
            if 'geo_info' in hop_data:
                hop.geographic_info = Mock(spec=GeographicInfo)
                hop.geographic_info.country_code = hop_data['geo_info'].get('country', 'US')
                hop.geographic_info.city = hop_data['geo_info'].get('city', 'Unknown')
                hop.geographic_info.isp = hop_data['geo_info'].get('isp', 'Unknown ISP')
            else:
                hop.geographic_info = None
            
            # Connection info
            if 'connection' in hop_data:
                hop.connection_info = Mock(spec=ConnectionInfo)
                hop.connection_info.source_port = hop_data['connection'].get('source_port', 80)
                hop.connection_info.destination_port = hop_data['connection'].get('dest_port', 443)
            else:
                hop.connection_info = None
            
            hops.append(hop)
        
        trace.hops = hops
        return trace
    
    def test_proxy_actor_properties(self):
        """Test basic proxy actor properties."""
        assert self.proxy_actor.actor_type == "proxy"
        assert self.proxy_actor.actor_category == ActorCategory.PROXY
        assert len(self.proxy_actor.patterns) > 0
    
    def test_proxy_detection_via_headers(self):
        """Test proxy detection via HTTP headers."""
        # Test X-Forwarded-For header
        trace = self.create_mock_trace_with_headers([
            {"name": "X-Forwarded-For", "value": "192.168.1.1, 10.0.0.1"}
        ])
        
        identification = self.proxy_actor.identify(trace)
        
        assert identification is not None
        assert identification.actor_type == "proxy"
        assert identification.confidence > 0.8
        assert any("X-Forwarded-For" in pattern for pattern in identification.patterns_matched)
    
    def test_proxy_detection_via_via_header(self):
        """Test proxy detection via Via header."""
        trace = self.create_mock_trace_with_headers([
            {"name": "Via", "value": "1.1 proxy.example.com"}
        ])
        
        identification = self.proxy_actor.identify(trace)
        
        assert identification is not None
        assert identification.confidence > 0.8
        assert any("Via" in pattern for pattern in identification.patterns_matched)
    
    def test_proxy_detection_via_datacenter_ip(self):
        """Test proxy detection via datacenter IP ranges."""
        # Use AWS IP range
        trace = self.create_mock_trace_with_hops([
            {"incoming_ip": "3.0.0.1", "outgoing_ip": "8.8.8.8"}
        ])
        
        identification = self.proxy_actor.identify(trace)
        
        assert identification is not None
        assert identification.confidence > 0.5
        assert any("datacenter" in pattern.lower() for pattern in identification.patterns_matched)
    
    def test_proxy_detection_via_response_content(self):
        """Test proxy detection via response content patterns."""
        trace = self.create_mock_trace_with_headers(
            [],
            response_body="Error: Proxy detected and blocked"
        )
        
        identification = self.proxy_actor.identify(trace)
        
        assert identification is not None
        assert identification.confidence > 0.8
        assert any("proxy detection" in pattern.lower() for pattern in identification.patterns_matched)
    
    def test_proxy_detection_multiple_patterns(self):
        """Test proxy detection with multiple matching patterns."""
        trace = self.create_mock_trace_with_headers(
            [{"name": "X-Forwarded-For", "value": "192.168.1.1"}],
            response_body="Datacenter IP detected"
        )
        
        # Add datacenter IP hop
        hop = Mock(spec=NetworkHop)
        hop.incoming_ip = "3.0.0.1"
        hop.outgoing_ip = "8.8.8.8"
        hop.geographic_info = None
        hop.connection_info = None
        trace.hops = [hop]
        
        identification = self.proxy_actor.identify(trace)
        
        assert identification is not None
        assert identification.confidence > 0.8
        assert len(identification.patterns_matched) >= 2
    
    def test_no_proxy_detection(self):
        """Test case where no proxy is detected."""
        trace = self.create_mock_trace_with_headers([
            {"name": "User-Agent", "value": "Mozilla/5.0"}
        ])
        
        identification = self.proxy_actor.identify(trace)
        
        # Should be None or very low confidence
        assert identification is None or identification.confidence < 0.3
    
    def test_behavior_analysis_high_risk(self):
        """Test behavior analysis for high-risk proxy scenario."""
        # Create identification with high detection likelihood
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.9,
            patterns_matched=[
                "X-Forwarded-For header indicates proxy usage",
                "Response content indicates proxy detection"
            ]
        )
        
        trace = self.create_mock_trace_with_headers(
            [{"name": "X-Forwarded-For", "value": "192.168.1.1"}],
            response_body="Proxy detected and blocked",
            status_code=403
        )
        
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        assert analysis.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert analysis.risk_score > 0.6
        assert analysis.detection_likelihood > 0.5
        assert len(analysis.recommendations) > 0
    
    def test_behavior_analysis_low_risk(self):
        """Test behavior analysis for low-risk proxy scenario."""
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.6,
            patterns_matched=["IP address from known datacenter/hosting provider"]
        )
        
        trace = self.create_mock_trace_with_hops([
            {"incoming_ip": "3.0.0.1", "outgoing_ip": "8.8.8.8"}
        ])
        
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        assert analysis.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM]
        assert analysis.risk_score < 0.7
        assert len(analysis.recommendations) > 0
    
    def test_anonymity_level_transparent(self):
        """Test anonymity level detection for transparent proxy."""
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.8,
            patterns_matched=["X-Forwarded-For header indicates proxy usage"]
        )
        
        trace = self.create_mock_trace_with_headers([
            {"name": "X-Forwarded-For", "value": "192.168.1.1"},
            {"name": "X-Real-IP", "value": "192.168.1.1"}
        ])
        
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        assert analysis.anonymity_level == AnonymityLevel.TRANSPARENT
    
    def test_anonymity_level_anonymous(self):
        """Test anonymity level detection for anonymous proxy."""
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.7,
            patterns_matched=["Via header indicates proxy in request path"]
        )
        
        trace = self.create_mock_trace_with_headers([
            {"name": "Via", "value": "1.1 proxy"}
        ])
        
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        assert analysis.anonymity_level == AnonymityLevel.ANONYMOUS
    
    def test_anonymity_level_elite(self):
        """Test anonymity level detection for elite proxy."""
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.6,
            patterns_matched=["IP address from known datacenter/hosting provider"]
        )
        
        # No revealing headers, only detected by IP
        trace = self.create_mock_trace_with_hops([
            {"incoming_ip": "3.0.0.1", "outgoing_ip": "8.8.8.8"}
        ])
        
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        assert analysis.anonymity_level == AnonymityLevel.ELITE
    
    def test_proxy_subtype_detection_residential(self):
        """Test residential proxy subtype detection."""
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.7,
            patterns_matched=["Residential proxy detection"]
        )
        
        trace = self.create_mock_trace_with_hops([
            {
                "incoming_ip": "192.168.1.1",
                "outgoing_ip": "8.8.8.8",
                "geo_info": {
                    "country": "US",
                    "city": "New York",
                    "isp": "Comcast Cable Communications"
                }
            }
        ])
        
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        assert analysis.characteristics['proxy_subtype'] == 'residential'
        assert len(analysis.characteristics['residential_indicators']) > 0
    
    def test_proxy_subtype_detection_datacenter(self):
        """Test datacenter proxy subtype detection."""
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.8,
            patterns_matched=["Datacenter IP detection"]
        )
        
        trace = self.create_mock_trace_with_hops([
            {
                "incoming_ip": "3.0.0.1",
                "outgoing_ip": "8.8.8.8",
                "geo_info": {
                    "country": "US",
                    "city": "Ashburn",
                    "isp": "Amazon Technologies Inc."
                }
            }
        ])
        
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        assert analysis.characteristics['proxy_subtype'] == 'datacenter'
        assert len(analysis.characteristics['datacenter_indicators']) > 0
    
    def test_proxy_subtype_detection_mobile(self):
        """Test mobile proxy subtype detection."""
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.7,
            patterns_matched=["Mobile proxy detection"]
        )
        
        trace = self.create_mock_trace_with_hops([
            {
                "incoming_ip": "192.168.1.1",
                "outgoing_ip": "8.8.8.8",
                "geo_info": {
                    "country": "US",
                    "city": "Los Angeles",
                    "isp": "Verizon Wireless"
                }
            }
        ])
        
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        assert analysis.characteristics['proxy_subtype'] == 'mobile'
    
    def test_performance_impact_assessment(self):
        """Test performance impact assessment."""
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.7,
            patterns_matched=["Proxy detection"]
        )
        
        # Test high latency scenario
        trace = self.create_mock_trace_with_headers([])
        trace.http_data.timing.total_time = 6000  # 6 seconds
        
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        assert "High latency" in analysis.performance_impact
        
        # Test low latency scenario
        trace.http_data.timing.total_time = 500  # 0.5 seconds
        
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        assert "Low latency" in analysis.performance_impact
    
    def test_recommendations_generation(self):
        """Test recommendation generation based on analysis."""
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.9,
            patterns_matched=[
                "X-Forwarded-For header indicates proxy usage",
                "Response content indicates proxy detection"
            ]
        )
        
        trace = self.create_mock_trace_with_headers(
            [{"name": "X-Forwarded-For", "value": "192.168.1.1"}],
            response_body="Proxy detected",
            status_code=403
        )
        
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        recommendations = analysis.recommendations
        
        # Should have recommendations for high-risk scenario
        assert len(recommendations) > 0
        assert any("residential" in rec.lower() for rec in recommendations)
        assert any("header" in rec.lower() for rec in recommendations)
    
    def test_webrtc_leak_detection(self):
        """Test WebRTC leak detection."""
        trace = self.create_mock_trace_with_headers(
            [],
            response_body="WebRTC leak detected: your real IP is exposed"
        )
        
        identification = self.proxy_actor.identify(trace)
        
        assert identification is not None
        assert any("webrtc" in pattern.lower() for pattern in identification.patterns_matched)
    
    def test_ip_leak_detection(self):
        """Test IP leak detection."""
        trace = self.create_mock_trace_with_headers(
            [],
            response_body="Real IP address detected: 192.168.1.1"
        )
        
        identification = self.proxy_actor.identify(trace)
        
        assert identification is not None
        assert any(re.search(r"ip.*leak", pattern.lower()) for pattern in identification.patterns_matched)
    
    def test_proxy_authorization_header(self):
        """Test proxy authorization header detection."""
        trace = self.create_mock_trace_with_headers([
            {"name": "Proxy-Authorization", "value": "Basic dXNlcjpwYXNz"}
        ])
        
        identification = self.proxy_actor.identify(trace)
        
        assert identification is not None
        assert identification.confidence > 0.9
        assert any("authorization" in pattern.lower() for pattern in identification.patterns_matched)
    
    def test_proxy_port_detection(self):
        """Test proxy port detection."""
        trace = self.create_mock_trace_with_hops([
            {
                "incoming_ip": "192.168.1.1",
                "outgoing_ip": "8.8.8.8",
                "connection": {
                    "source_port": 12345,
                    "dest_port": 8080  # Common proxy port
                }
            }
        ])
        
        identification = self.proxy_actor.identify(trace)
        
        assert identification is not None
        assert any("proxy port" in pattern.lower() for pattern in identification.patterns_matched)
    
    def test_get_proxy_subtypes(self):
        """Test getting proxy subtypes."""
        subtypes = self.proxy_actor.get_proxy_subtypes()
        
        assert isinstance(subtypes, list)
        assert len(subtypes) > 0
        assert "http_proxy" in subtypes
        assert "socks5_proxy" in subtypes
    
    def test_identify_proxy_subtype(self):
        """Test proxy subtype identification."""
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.8,
            patterns_matched=["X-Forwarded-For header indicates proxy usage"]
        )
        
        trace = self.create_mock_trace_with_headers([
            {"name": "X-Forwarded-For", "value": "192.168.1.1"}
        ])
        
        subtype = self.proxy_actor.identify_proxy_subtype(trace, identification)
        
        assert subtype == "http_proxy"
    
    def test_geographic_consistency_analysis(self):
        """Test geographic consistency analysis."""
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.7,
            patterns_matched=["Proxy detection"]
        )
        
        trace = self.create_mock_trace_with_hops([
            {
                "incoming_ip": "192.168.1.1",
                "outgoing_ip": "8.8.8.8",
                "geo_info": {
                    "country": "US",
                    "city": "New York",
                    "isp": "Example ISP"
                }
            },
            {
                "incoming_ip": "10.0.0.1",
                "outgoing_ip": "192.168.1.1",
                "geo_info": {
                    "country": "DE",  # Different country
                    "city": "Berlin",
                    "isp": "German ISP"
                }
            }
        ])
        
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        # Should have geographic information in characteristics
        assert 'geographic_info' in analysis.characteristics
        assert len(analysis.characteristics['geographic_info']) == 2
    
    def test_error_handling_invalid_data(self):
        """Test error handling with invalid data."""
        identification = ActorIdentification(
            actor_type="proxy",
            actor_category=ActorCategory.PROXY,
            confidence=0.7,
            patterns_matched=["Test pattern"]
        )
        
        # Create trace with invalid/missing data
        trace = Mock(spec=NetworkTrace)
        trace.is_http.return_value = True
        trace.http_data = None  # Invalid data
        trace.hops = []
        
        # Should not raise exception
        analysis = self.proxy_actor.analyze_behavior(trace, identification)
        
        assert analysis is not None
        assert isinstance(analysis, BehaviorAnalysis)


if __name__ == "__main__":
    pytest.main([__file__])
