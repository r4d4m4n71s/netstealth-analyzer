"""
Unit tests for the ProxyDetector class.

This module contains comprehensive unit tests to validate the functionality
of the ProxyDetector in detecting proxy-related stealth issues.
"""

import pytest
from unittest.mock import AsyncMock
from datetime import datetime, timezone

from netstealth_analyzer.detectors.proxy import ProxyDetector
from netstealth_analyzer.models.network import NetworkTrace, HttpRequest, HttpResponse
from netstealth_analyzer.detectors.base import DetectionContext
from netstealth_analyzer.models.enums import (
    SeverityLevel, 
    IssueCategory, 
    DetectionConfidence
)


@pytest.fixture
def proxy_detector():
    """Fixture to create a ProxyDetector instance for testing."""
    return ProxyDetector()


@pytest.mark.asyncio
async def test_proxy_detector_initialization(proxy_detector):
    """Test ProxyDetector initialization and basic properties."""
    assert proxy_detector.name == "Proxy Detection Detector"
    assert proxy_detector.version == "2.0.0"
    assert IssueCategory.PROXY_DETECTION in proxy_detector.categories
    assert IssueCategory.IP_EXPOSURE in proxy_detector.categories
    assert len(proxy_detector.detection_rules) > 0


@pytest.mark.asyncio
async def test_proxy_headers_detection(proxy_detector):
    """Test detection of proxy-revealing headers."""
    mock_trace = AsyncMock(spec=NetworkTrace)
    mock_trace.configure_mock(
        trace_id="test_proxy_headers",
        request=HttpRequest(
            method="GET",
            url="https://example.com/api",
            headers=[
                {"name": "X-Forwarded-For", "value": "192.168.1.100"},
                {"name": "Via", "value": "1.1 proxy.example.com"},
                {"name": "X-Real-IP", "value": "10.0.0.1"}
            ]
        ),
        response=HttpResponse(
            status_code=200,
            body="Normal response",
            headers=[]
        ),
        timestamp=datetime.now(timezone.utc)
    )

    context = DetectionContext(
        network_traces=[mock_trace],
        confidence_threshold=0.5,
        service_domains=['example.com']
    )

    result = await proxy_detector.detect(context)

    assert len(result.issues_found) > 0
    issue = result.issues_found[0]
    assert issue.category == IssueCategory.PROXY_DETECTION
    assert issue.severity == SeverityLevel.MEDIUM
    assert "proxy headers" in issue.title.lower()


@pytest.mark.asyncio
async def test_proxy_detection_messages(proxy_detector):
    """Test detection of proxy detection messages in response."""
    mock_trace = AsyncMock(spec=NetworkTrace)
    mock_trace.configure_mock(
        trace_id="test_proxy_detection",
        request=HttpRequest(
            method="GET",
            url="https://example.com/api",
            headers=[]
        ),
        response=HttpResponse(
            status_code=403,
            body="Proxy detected. Access denied from proxy networks.",
            headers=[]
        ),
        timestamp=datetime.now(timezone.utc)
    )

    context = DetectionContext(
        network_traces=[mock_trace],
        confidence_threshold=0.5,
        service_domains=['example.com']
    )

    result = await proxy_detector.detect(context)

    assert len(result.issues_found) > 0
    issue = result.issues_found[0]
    assert issue.category == IssueCategory.PROXY_DETECTION
    assert issue.severity == SeverityLevel.HIGH
    assert "proxy usage detected" in issue.title.lower()


@pytest.mark.asyncio
async def test_ip_leak_detection(proxy_detector):
    """Test detection of IP leak indicators."""
    mock_trace = AsyncMock(spec=NetworkTrace)
    mock_trace.configure_mock(
        trace_id="test_ip_leak",
        request=HttpRequest(
            method="GET",
            url="https://example.com/test",
            headers=[]
        ),
        response=HttpResponse(
            status_code=200,
            body="Real IP detected: Your actual IP address has been found despite proxy usage.",
            headers=[]
        ),
        timestamp=datetime.now(timezone.utc)
    )

    context = DetectionContext(
        network_traces=[mock_trace],
        confidence_threshold=0.5,
        service_domains=['example.com']
    )

    result = await proxy_detector.detect(context)

    assert len(result.issues_found) > 0
    issue = result.issues_found[0]
    assert issue.category == IssueCategory.IP_EXPOSURE
    assert issue.severity == SeverityLevel.CRITICAL
    assert "ip address leak" in issue.title.lower()


@pytest.mark.asyncio
async def test_webrtc_leak_detection(proxy_detector):
    """Test detection of WebRTC leaks."""
    mock_trace = AsyncMock(spec=NetworkTrace)
    mock_trace.configure_mock(
        trace_id="test_webrtc_leak",
        request=HttpRequest(
            method="GET",
            url="https://webrtc-test.com/stun-server-check",
            headers=[]
        ),
        response=HttpResponse(
            status_code=200,
            body="WebRTC leak detected: STUN servers are exposing your real IP",
            headers=[]
        ),
        timestamp=datetime.now(timezone.utc)
    )

    context = DetectionContext(
        network_traces=[mock_trace],
        confidence_threshold=0.5,
        service_domains=['webrtc-test.com']
    )

    result = await proxy_detector.detect(context)

    assert len(result.issues_found) > 0
    issue = result.issues_found[0]
    # WebRTC leaks are categorized as IP_EXPOSURE in the actual implementation
    assert issue.category == IssueCategory.IP_EXPOSURE
    assert issue.severity == SeverityLevel.CRITICAL
    # The actual implementation creates an "IP Address Leak Detected" issue for WebRTC patterns
    assert "ip address leak" in issue.title.lower()


@pytest.mark.asyncio
async def test_datacenter_ip_detection(proxy_detector):
    """Test detection of datacenter IP identification."""
    mock_trace = AsyncMock(spec=NetworkTrace)
    mock_trace.configure_mock(
        trace_id="test_datacenter_ip",
        request=HttpRequest(
            method="GET",
            url="https://example.com/check-ip",
            headers=[]
        ),
        response=HttpResponse(
            status_code=200,
            body="Datacenter IP detected: Your IP belongs to a hosting provider",
            headers=[]
        ),
        timestamp=datetime.now(timezone.utc)
    )

    context = DetectionContext(
        network_traces=[mock_trace],
        confidence_threshold=0.5,
        service_domains=['example.com']
    )

    result = await proxy_detector.detect(context)

    assert len(result.issues_found) > 0
    issue = result.issues_found[0]
    assert issue.category == IssueCategory.PROXY_DETECTION
    assert issue.severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH]
    # The actual implementation creates a "Proxy Usage Detected" issue for datacenter patterns
    assert "proxy usage detected" in issue.title.lower()


@pytest.mark.asyncio
async def test_ip_detection_service_leak(proxy_detector):
    """Test detection of IP leaks through IP detection services."""
    mock_trace = AsyncMock(spec=NetworkTrace)
    mock_trace.configure_mock(
        trace_id="test_ip_service",
        request=HttpRequest(
            method="GET",
            url="https://ipinfo.io/json",
            headers=[]
        ),
        response=HttpResponse(
            status_code=200,
            body='{"ip": "203.0.113.1", "city": "Example City"}',
            headers=[]
        ),
        timestamp=datetime.now(timezone.utc)
    )

    context = DetectionContext(
        network_traces=[mock_trace],
        confidence_threshold=0.5,
        service_domains=[]
    )

    result = await proxy_detector.detect(context)

    assert len(result.issues_found) > 0
    issue = result.issues_found[0]
    assert issue.category == IssueCategory.IP_EXPOSURE
    assert issue.severity == SeverityLevel.HIGH
    assert "ip detection service" in issue.title.lower()


@pytest.mark.asyncio
async def test_consistent_proxy_detection(proxy_detector):
    """Test detection of consistent proxy detection across multiple requests."""
    mock_traces = []
    
    # Create multiple traces with proxy detection messages
    for i in range(10):
        mock_trace = AsyncMock(spec=NetworkTrace)
        mock_trace.configure_mock(
            trace_id=f"test_trace_{i}",
            request=HttpRequest(
                method="GET",
                url=f"https://example.com/api/{i}",
                headers=[]
            ),
            response=HttpResponse(
                status_code=403 if i < 6 else 200,  # 6 out of 10 show proxy detection
                body="Proxy detected and blocked" if i < 6 else "Normal response",
                headers=[]
            ),
            timestamp=datetime.now(timezone.utc)
        )
        mock_traces.append(mock_trace)

    context = DetectionContext(
        network_traces=mock_traces,
        confidence_threshold=0.5,
        service_domains=['example.com']
    )

    result = await proxy_detector.detect(context)

    # Should find consistent proxy detection issue
    consistent_detection_issues = [
        issue for issue in result.issues_found 
        if "consistent proxy detection" in issue.title.lower()
    ]
    assert len(consistent_detection_issues) > 0
    
    issue = consistent_detection_issues[0]
    assert issue.category == IssueCategory.PROXY_DETECTION
    assert issue.severity == SeverityLevel.CRITICAL


@pytest.mark.asyncio
async def test_ip_inconsistency_detection(proxy_detector):
    """Test detection of IP inconsistencies across traces."""
    mock_traces = []
    
    # Create traces to different IP detection services with different IPs
    ip_services = ['ipinfo.io', 'httpbin.org/ip', 'icanhazip.com']
    ips = ['203.0.113.1', '198.51.100.1', '192.0.2.1']
    
    for i, (service, ip) in enumerate(zip(ip_services, ips)):
        mock_trace = AsyncMock(spec=NetworkTrace)
        mock_trace.configure_mock(
            trace_id=f"ip_trace_{i}",
            request=HttpRequest(
                method="GET",
                url=f"https://{service}",
                headers=[]
            ),
            response=HttpResponse(
                status_code=200,
                body=f'{{"ip": "{ip}"}}',
                headers=[]
            ),
            timestamp=datetime.now(timezone.utc)
        )
        mock_traces.append(mock_trace)

    context = DetectionContext(
        network_traces=mock_traces,
        confidence_threshold=0.5,
        service_domains=[]
    )

    result = await proxy_detector.detect(context)

    # Should find IP inconsistency issue
    ip_inconsistency_issues = [
        issue for issue in result.issues_found 
        if "multiple ip addresses" in issue.title.lower()
    ]
    assert len(ip_inconsistency_issues) > 0
    
    issue = ip_inconsistency_issues[0]
    assert issue.category == IssueCategory.IP_EXPOSURE
    assert issue.severity == SeverityLevel.MEDIUM


@pytest.mark.asyncio
async def test_empty_traces_handling(proxy_detector):
    """Test handling of empty network traces."""
    context = DetectionContext(
        network_traces=[],
        confidence_threshold=0.5,
        service_domains=[]
    )

    result = await proxy_detector.detect(context)

    assert len(result.issues_found) == 0
    assert result.statistics['traces_analyzed'] == 0


@pytest.mark.asyncio
async def test_confidence_threshold_filtering(proxy_detector):
    """Test filtering of issues based on confidence threshold."""
    mock_trace = AsyncMock(spec=NetworkTrace)
    mock_trace.configure_mock(
        trace_id="test_threshold",
        request=HttpRequest(
            method="GET",
            url="https://example.com/api",
            headers=[{"name": "X-Forwarded-For", "value": "192.168.1.1"}]
        ),
        response=HttpResponse(
            status_code=200,
            body="Normal response",
            headers=[]
        ),
        timestamp=datetime.now(timezone.utc)
    )

    # Test with high threshold that should filter out medium confidence issues
    context = DetectionContext(
        network_traces=[mock_trace],
        confidence_threshold=0.9,  # High threshold
        service_domains=['example.com']
    )

    result = await proxy_detector.detect(context)

    # Proxy headers issue has medium confidence, should be filtered out
    assert len(result.issues_found) == 0


@pytest.mark.asyncio
async def test_multiple_proxy_indicators(proxy_detector):
    """Test detection when multiple proxy indicators are present."""
    mock_trace = AsyncMock(spec=NetworkTrace)
    mock_trace.configure_mock(
        trace_id="test_multiple_indicators",
        request=HttpRequest(
            method="GET",
            url="https://example.com/api",
            headers=[
                {"name": "X-Forwarded-For", "value": "192.168.1.100"},
                {"name": "Via", "value": "1.1 proxy.example.com"}
            ]
        ),
        response=HttpResponse(
            status_code=403,
            body="Using proxy detected. Datacenter IP blocked.",
            headers=[]
        ),
        timestamp=datetime.now(timezone.utc)
    )

    context = DetectionContext(
        network_traces=[mock_trace],
        confidence_threshold=0.5,
        service_domains=['example.com']
    )

    result = await proxy_detector.detect(context)

    # Should find multiple different types of issues
    assert len(result.issues_found) >= 2
    
    categories = [issue.category for issue in result.issues_found]
    assert IssueCategory.PROXY_DETECTION in categories


@pytest.mark.asyncio
async def test_vpn_detection_patterns(proxy_detector):
    """Test detection of VPN-specific patterns."""
    mock_trace = AsyncMock(spec=NetworkTrace)
    mock_trace.configure_mock(
        trace_id="test_vpn_detection",
        request=HttpRequest(
            method="GET",
            url="https://example.com/protected",
            headers=[]
        ),
        response=HttpResponse(
            status_code=403,
            body="VPN detected. Please disable your VPN to access this service.",
            headers=[]
        ),
        timestamp=datetime.now(timezone.utc)
    )

    context = DetectionContext(
        network_traces=[mock_trace],
        confidence_threshold=0.5,
        service_domains=['example.com']
    )

    result = await proxy_detector.detect(context)

    assert len(result.issues_found) > 0
    issue = result.issues_found[0]
    assert issue.category == IssueCategory.PROXY_DETECTION
    assert issue.severity == SeverityLevel.HIGH


@pytest.mark.asyncio
async def test_dns_leak_detection(proxy_detector):
    """Test detection of DNS leak indicators."""
    mock_trace = AsyncMock(spec=NetworkTrace)
    mock_trace.configure_mock(
        trace_id="test_dns_leak",
        request=HttpRequest(
            method="GET",
            url="https://dnsleaktest.com/test",
            headers=[]
        ),
        response=HttpResponse(
            status_code=200,
            body="DNS leak detected: Your DNS requests are not going through the proxy",
            headers=[]
        ),
        timestamp=datetime.now(timezone.utc)
    )

    context = DetectionContext(
        network_traces=[mock_trace],
        confidence_threshold=0.5,
        service_domains=['dnsleaktest.com']
    )

    result = await proxy_detector.detect(context)

    assert len(result.issues_found) > 0
    issue = result.issues_found[0]
    assert issue.category == IssueCategory.IP_EXPOSURE
    assert issue.severity == SeverityLevel.CRITICAL


@pytest.mark.asyncio
async def test_proxy_service_domain_detection(proxy_detector):
    """Test detection of requests to known proxy service domains."""
    # Test internal method for proxy service domain detection
    assert proxy_detector._is_ip_detection_service('ipinfo.io')
    assert proxy_detector._is_ip_detection_service('whatismyipaddress.com')
    assert proxy_detector._is_ip_detection_service('httpbin.org')
    assert not proxy_detector._is_ip_detection_service('google.com')


@pytest.mark.asyncio
async def test_domain_extraction_utility(proxy_detector):
    """Test domain extraction utility method."""
    assert proxy_detector._extract_domain('https://example.com/path') == 'example.com'
    assert proxy_detector._extract_domain('http://sub.example.com:8080/path') == 'sub.example.com:8080'
    assert proxy_detector._extract_domain('invalid-url') == ''


@pytest.mark.asyncio
async def test_service_domain_matching(proxy_detector):
    """Test service domain matching logic."""
    service_domains = ['example.com', 'test.org']
    
    assert proxy_detector._is_service_domain('example.com', service_domains)
    assert proxy_detector._is_service_domain('api.example.com', service_domains)
    assert proxy_detector._is_service_domain('test.org', service_domains)
    assert not proxy_detector._is_service_domain('other.com', service_domains)
    assert not proxy_detector._is_service_domain('example.net', service_domains)


@pytest.mark.asyncio
async def test_no_proxy_indicators_clean_trace(proxy_detector):
    """Test trace without any proxy indicators."""
    mock_trace = AsyncMock(spec=NetworkTrace)
    mock_trace.configure_mock(
        trace_id="test_clean",
        request=HttpRequest(
            method="GET",
            url="https://example.com/api",
            headers=[{"name": "User-Agent", "value": "Normal Browser"}]
        ),
        response=HttpResponse(
            status_code=200,
            body="Normal response without any proxy indicators",
            headers=[]
        ),
        timestamp=datetime.now(timezone.utc)
    )

    context = DetectionContext(
        network_traces=[mock_trace],
        confidence_threshold=0.5,
        service_domains=['example.com']
    )

    result = await proxy_detector.detect(context)

    # Should not find any proxy-related issues
    assert len(result.issues_found) == 0
    assert result.statistics['traces_analyzed'] == 1
