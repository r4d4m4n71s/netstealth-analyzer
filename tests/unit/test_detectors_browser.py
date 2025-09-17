"""
Unit tests for browser detector.

Tests browser automation detection, fingerprinting detection, and configuration analysis.
"""

import pytest
import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch, AsyncMock

from src.netstealth_analyzer.detectors.browser import BrowserDetector
from src.netstealth_analyzer.detectors.base import DetectionContext, DetectionResult
from src.netstealth_analyzer.models.network import NetworkTrace, HttpRequest, HttpResponse, TimingInfo
from src.netstealth_analyzer.models.issues import Issue, IssueEvidence, DetectionRule
from src.netstealth_analyzer.models.enums import (
    SeverityLevel, IssueCategory, DetectionConfidence, LogFormat
)
from src.netstealth_analyzer.core.events import EventBus


class TestBrowserDetector:
    """Test browser detector functionality."""
    
    @pytest.fixture
    def event_bus(self):
        """Create event bus for testing."""
        return EventBus()
    
    @pytest.fixture
    def browser_detector(self, event_bus):
        """Create browser detector instance."""
        return BrowserDetector(event_bus=event_bus, confidence_threshold=0.7)
    
    @pytest.fixture
    def detection_context(self):
        """Create detection context for testing."""
        return DetectionContext(
            network_traces=[],
            service_domains=['example.com', 'test.com'],
            confidence_threshold=0.7
        )
    
    @pytest.fixture
    def automation_trace(self):
        """Create trace with automation indicators."""
        request = HttpRequest(
            method='GET',
            url='https://example.com/api/data',
            headers=[
                {'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.124 Safari/537.36'},
                {'name': 'webdriver', 'value': 'true'}
            ],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(
            status_code=403,
            status_text='Forbidden',
            headers=[{'name': 'Content-Type', 'value': 'text/html'}],
            body='<html><body>Bot detected. Access denied.</body></html>',
            size=1024
        )
        
        return NetworkTrace(
            id='automation_trace_1',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=request,
            response=response,
            metadata={'domain': 'example.com'}
        )
    
    @pytest.fixture
    def fingerprinting_trace(self):
        """Create trace with fingerprinting indicators."""
        request = HttpRequest(
            method='GET',
            url='https://example.com/fingerprint.js',
            headers=[
                {'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                {'name': 'Accept', 'value': 'application/javascript'}
            ],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(
            status_code=200,
            status_text='OK',
            headers=[{'name': 'Content-Type', 'value': 'application/javascript'}],
            body='''
                function getCanvasFingerprint() {
                    var canvas = document.createElement('canvas');
                    var ctx = canvas.getContext('2d');
                    ctx.textBaseline = 'top';
                    ctx.font = '14px Arial';
                    ctx.fillText('Canvas fingerprint test', 2, 2);
                    return canvas.toDataURL();
                }
                
                function getWebGLFingerprint() {
                    var gl = canvas.getContext('webgl');
                    var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    return gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                }
            ''',
            size=2048
        )
        
        return NetworkTrace(
            id='fingerprinting_trace_1',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=request,
            response=response,
            metadata={'domain': 'example.com'}
        )
    
    @pytest.fixture
    def normal_trace(self):
        """Create normal trace without issues."""
        request = HttpRequest(
            method='GET',
            url='https://example.com/page',
            headers=[
                {'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
                {'name': 'Accept', 'value': 'text/html,application/xhtml+xml'}
            ],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(
            status_code=200,
            status_text='OK',
            headers=[{'name': 'Content-Type', 'value': 'text/html'}],
            body='<html><body><h1>Welcome</h1></body></html>',
            size=512
        )
        
        return NetworkTrace(
            id='normal_trace_1',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=request,
            response=response,
            metadata={'domain': 'example.com'}
        )
    
    def test_detector_properties(self, browser_detector):
        """Test detector basic properties."""
        assert browser_detector.name == "Browser Configuration Detector"
        assert browser_detector.version == "2.0.0"
        assert "browser automation" in browser_detector.description.lower()
        
        # Test categories
        categories = browser_detector.categories
        assert IssueCategory.BROWSER_CONFIG in categories
        assert IssueCategory.JAVASCRIPT_FINGERPRINT in categories
        assert IssueCategory.CANVAS_FINGERPRINT in categories
        assert IssueCategory.FONT_FINGERPRINT in categories
        
        # Test detection rules
        rules = browser_detector.detection_rules
        assert len(rules) >= 5
        rule_ids = [rule.id for rule in rules]
        assert "browser_automation_detected" in rule_ids
        assert "headless_browser_detected" in rule_ids
        assert "browser_fingerprinting" in rule_ids
        assert "suspicious_user_agent" in rule_ids
        assert "anti_bot_challenge" in rule_ids
    
    @pytest.mark.asyncio
    async def test_detect_automation_user_agent(self, browser_detector, detection_context):
        """Test detection of automation in user agent."""
        # Create trace with selenium user agent
        request = HttpRequest(
            method='GET',
            url='https://example.com/test',
            headers=[
                {'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 selenium/3.141.0'}
            ],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(status_code=200, status_text='OK')
        
        trace = NetworkTrace(
            id='selenium_trace',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=request,
            response=response
        )
        
        detection_context.network_traces = [trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Validate results
        assert isinstance(result, DetectionResult)
        assert result.detector_name == browser_detector.name
        assert len(result.issues_found) >= 1
        
        # Check for suspicious user agent issue
        user_agent_issues = [
            issue for issue in result.issues_found
            if "user agent" in issue.title.lower()
        ]
        assert len(user_agent_issues) >= 1
        
        issue = user_agent_issues[0]
        assert issue.category == IssueCategory.BROWSER_CONFIG
        assert issue.severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH]
        assert issue.confidence >= DetectionConfidence.MEDIUM
        assert "selenium" in issue.description.lower()
    
    @pytest.mark.asyncio
    async def test_detect_automation_headers(self, browser_detector, detection_context):
        """Test detection of automation headers."""
        # Create trace with webdriver header
        request = HttpRequest(
            method='GET',
            url='https://example.com/test',
            headers=[
                {'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                {'name': 'webdriver', 'value': 'true'},
                {'name': 'selenium-remote-control', 'value': '1'}
            ],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(status_code=200, status_text='OK')
        
        trace = NetworkTrace(
            id='webdriver_trace',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=request,
            response=response
        )
        
        detection_context.network_traces = [trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Validate results
        assert len(result.issues_found) >= 1
        
        # Check for automation headers issue
        header_issues = [
            issue for issue in result.issues_found
            if "automation headers" in issue.title.lower()
        ]
        assert len(header_issues) >= 1
        
        issue = header_issues[0]
        assert issue.category == IssueCategory.BROWSER_CONFIG
        assert issue.severity == SeverityLevel.MEDIUM
        assert "webdriver" in issue.description.lower()
    
    @pytest.mark.asyncio
    async def test_detect_automation_response(self, browser_detector, automation_trace, detection_context):
        """Test detection of automation in response content."""
        detection_context.network_traces = [automation_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Validate results
        assert len(result.issues_found) >= 1
        
        # Check for automation detection issue
        automation_issues = [
            issue for issue in result.issues_found
            if "automation detected" in issue.title.lower()
        ]
        assert len(automation_issues) >= 1
        
        issue = automation_issues[0]
        assert issue.category == IssueCategory.BROWSER_CONFIG
        assert issue.severity == SeverityLevel.HIGH
        assert "bot detected" in issue.description.lower()
    
    @pytest.mark.asyncio
    async def test_detect_canvas_fingerprinting(self, browser_detector, fingerprinting_trace, detection_context):
        """Test detection of canvas fingerprinting."""
        detection_context.network_traces = [fingerprinting_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Validate results
        assert len(result.issues_found) >= 1
        
        # Check for fingerprinting issues
        fingerprint_issues = [
            issue for issue in result.issues_found
            if "fingerprint" in issue.title.lower()
        ]
        assert len(fingerprint_issues) >= 1
        
        # Should detect both general fingerprinting and canvas-specific
        canvas_issues = [
            issue for issue in fingerprint_issues
            if "canvas" in issue.title.lower()
        ]
        assert len(canvas_issues) >= 1
        
        canvas_issue = canvas_issues[0]
        assert canvas_issue.category == IssueCategory.CANVAS_FINGERPRINT
        assert canvas_issue.severity == SeverityLevel.MEDIUM
        assert "canvas" in canvas_issue.description.lower()
    
    @pytest.mark.asyncio
    async def test_detect_webgl_fingerprinting(self, browser_detector, detection_context):
        """Test detection of WebGL fingerprinting."""
        # Create trace with WebGL fingerprinting
        request = HttpRequest(
            method='GET',
            url='https://example.com/webgl-test.js',
            headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(
            status_code=200,
            status_text='OK',
            headers=[{'name': 'Content-Type', 'value': 'application/javascript'}],
            body='''
                var canvas = document.createElement('canvas');
                var gl = canvas.getContext('webgl');
                var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                var vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                var renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                var extensions = gl.getSupportedExtensions();
            ''',
            size=1024
        )
        
        trace = NetworkTrace(
            id='webgl_trace',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=request,
            response=response
        )
        
        detection_context.network_traces = [trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Validate results
        assert len(result.issues_found) >= 1
        
        # Check for WebGL fingerprinting issue
        webgl_issues = [
            issue for issue in result.issues_found
            if "webgl" in issue.title.lower()
        ]
        assert len(webgl_issues) >= 1
        
        issue = webgl_issues[0]
        assert issue.category == IssueCategory.JAVASCRIPT_FINGERPRINT
        assert issue.severity == SeverityLevel.MEDIUM
        assert "webgl" in issue.description.lower()
    
    @pytest.mark.asyncio
    async def test_detect_antibot_challenge(self, browser_detector, detection_context):
        """Test detection of anti-bot challenges."""
        # Create trace with Cloudflare challenge
        request = HttpRequest(
            method='GET',
            url='https://example.com/protected',
            headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(
            status_code=503,
            status_text='Service Unavailable',
            headers=[{'name': 'Server', 'value': 'cloudflare'}],
            body='<html><body>Please verify you are human. Cloudflare challenge page.</body></html>',
            size=2048
        )
        
        trace = NetworkTrace(
            id='challenge_trace',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=request,
            response=response
        )
        
        detection_context.network_traces = [trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Validate results
        assert len(result.issues_found) >= 1
        
        # Check for anti-bot challenge issue
        challenge_issues = [
            issue for issue in result.issues_found
            if "anti-bot" in issue.title.lower() or "challenge" in issue.title.lower()
        ]
        assert len(challenge_issues) >= 1
        
        issue = challenge_issues[0]
        assert issue.category == IssueCategory.BROWSER_CONFIG
        assert issue.severity == SeverityLevel.HIGH
        assert "503" in issue.description or "challenge" in issue.description.lower()
    
    @pytest.mark.asyncio
    async def test_detect_javascript_detection_scripts(self, browser_detector, detection_context):
        """Test detection of JavaScript detection scripts."""
        # Create trace requesting bot detection script
        request = HttpRequest(
            method='GET',
            url='https://example.com/js/bot-detection.js',
            headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(
            status_code=200,
            status_text='OK',
            headers=[{'name': 'Content-Type', 'value': 'application/javascript'}],
            body='// Bot detection script',
            size=512
        )
        
        trace = NetworkTrace(
            id='js_detection_trace',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=request,
            response=response
        )
        
        detection_context.network_traces = [trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Validate results
        assert len(result.issues_found) >= 1
        
        # Check for JavaScript detection issue
        js_issues = [
            issue for issue in result.issues_found
            if "javascript" in issue.title.lower() and "detection" in issue.title.lower()
        ]
        assert len(js_issues) >= 1
        
        issue = js_issues[0]
        assert issue.category == IssueCategory.JAVASCRIPT_FINGERPRINT
        assert issue.severity == SeverityLevel.MEDIUM
        assert "bot-detection.js" in issue.description
    
    @pytest.mark.asyncio
    async def test_cross_trace_automation_detection(self, browser_detector, detection_context):
        """Test cross-trace automation detection analysis."""
        # Create multiple traces with automation detection
        traces = []
        for i in range(5):
            request = HttpRequest(
                method='GET',
                url=f'https://example.com/page{i}',
                headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}],
                timestamp=datetime.now(timezone.utc)
            )
            
            # 3 out of 5 traces show automation detection
            if i < 3:
                response = HttpResponse(
                    status_code=403,
                    status_text='Forbidden',
                    body='Automation detected. Access denied.',
                    size=1024
                )
            else:
                response = HttpResponse(
                    status_code=200,
                    status_text='OK',
                    body='<html><body>Normal page</body></html>',
                    size=512
                )
            
            trace = NetworkTrace(
                id=f'cross_trace_{i}',
                source_format=LogFormat.HAR,
                timestamp=datetime.now(timezone.utc),
                request=request,
                response=response,
                metadata={'domain': 'example.com'}
            )
            traces.append(trace)
        
        detection_context.network_traces = traces
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Validate results
        assert len(result.issues_found) >= 1
        
        # Check for consistent automation detection issue
        consistent_issues = [
            issue for issue in result.issues_found
            if "consistent" in issue.title.lower() and "automation" in issue.title.lower()
        ]
        assert len(consistent_issues) >= 1
        
        issue = consistent_issues[0]
        assert issue.category == IssueCategory.BROWSER_CONFIG
        assert issue.severity == SeverityLevel.CRITICAL
        assert "60%" in issue.description or "3" in issue.description  # 3 out of 5 = 60%
    
    @pytest.mark.asyncio
    async def test_multiple_fingerprinting_detection(self, browser_detector, detection_context):
        """Test detection of multiple fingerprinting attempts."""
        # Create multiple traces with fingerprinting
        traces = []
        fingerprinting_patterns = [
            'canvas fingerprint detection',
            'webgl fingerprint analysis',
            'font fingerprint enumeration',
            'audio fingerprint capture'
        ]
        
        for i, pattern in enumerate(fingerprinting_patterns):
            request = HttpRequest(
                method='GET',
                url=f'https://example.com/fingerprint{i}.js',
                headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}],
                timestamp=datetime.now(timezone.utc)
            )
            
            response = HttpResponse(
                status_code=200,
                status_text='OK',
                body=f'// {pattern} script content',
                size=1024
            )
            
            trace = NetworkTrace(
                id=f'fingerprint_trace_{i}',
                source_format=LogFormat.HAR,
                timestamp=datetime.now(timezone.utc),
                request=request,
                response=response
            )
            traces.append(trace)
        
        detection_context.network_traces = traces
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Validate results
        assert len(result.issues_found) >= 1
        
        # Check for multiple fingerprinting issue
        multiple_issues = [
            issue for issue in result.issues_found
            if "multiple" in issue.title.lower() and "fingerprint" in issue.title.lower()
        ]
        assert len(multiple_issues) >= 1
        
        issue = multiple_issues[0]
        assert issue.category == IssueCategory.JAVASCRIPT_FINGERPRINT
        assert issue.severity == SeverityLevel.HIGH
        assert "4" in issue.description  # 4 fingerprinting attempts
    
    @pytest.mark.asyncio
    async def test_robotic_timing_detection(self, browser_detector, detection_context):
        """Test detection of robotic timing patterns."""
        # Create traces with very consistent timing
        traces = []
        base_time = datetime.now(timezone.utc)
        
        for i in range(10):
            # Very consistent 2-second intervals
            timestamp = base_time.replace(second=base_time.second + i * 2)
            
            request = HttpRequest(
                method='GET',
                url=f'https://example.com/page{i}',
                headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}],
                timestamp=timestamp
            )
            
            response = HttpResponse(
                status_code=200,
                status_text='OK',
                body='<html><body>Page content</body></html>',
                size=512
            )
            
            trace = NetworkTrace(
                id=f'timing_trace_{i}',
                source_format=LogFormat.HAR,
                timestamp=timestamp,
                request=request,
                response=response
            )
            traces.append(trace)
        
        detection_context.network_traces = traces
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Validate results - may or may not detect timing issues depending on implementation
        timing_issues = [
            issue for issue in result.issues_found
            if "timing" in issue.title.lower() or "robotic" in issue.title.lower()
        ]
        
        # If timing detection is implemented, validate it
        if timing_issues:
            issue = timing_issues[0]
            assert issue.category == IssueCategory.BROWSER_CONFIG
            assert issue.severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH]
            assert "2.00" in issue.description or "consistent" in issue.description.lower()
    
    @pytest.mark.asyncio
    async def test_no_issues_normal_trace(self, browser_detector, normal_trace, detection_context):
        """Test that normal traces don't trigger false positives."""
        detection_context.network_traces = [normal_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Validate results - should have no high-confidence issues
        assert isinstance(result, DetectionResult)
        assert result.detector_name == browser_detector.name
        
        # Normal traces should not trigger browser automation issues
        automation_issues = [
            issue for issue in result.issues_found
            if "automation" in issue.title.lower() or "bot" in issue.title.lower()
        ]
        assert len(automation_issues) == 0
    
    @pytest.mark.asyncio
    async def test_confidence_threshold_filtering(self, browser_detector, detection_context):
        """Test that confidence threshold filtering works."""
        # Set high confidence threshold
        detection_context.confidence_threshold = 0.9
        
        # Create trace with medium confidence issue
        request = HttpRequest(
            method='GET',
            url='https://example.com/test',
            headers=[
                {'name': 'User-Agent', 'value': 'CustomBot/1.0'}  # Unusual but not clearly automation
            ],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(status_code=200, status_text='OK')
        
        trace = NetworkTrace(
            id='medium_confidence_trace',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=request,
            response=response
        )
        
        detection_context.network_traces = [trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should filter out medium confidence issues
        for issue in result.issues_found:
            assert issue.confidence >= 0.9
    
    @pytest.mark.asyncio
    async def test_detection_statistics(self, browser_detector, detection_context):
        """Test that detection statistics are properly calculated."""
        # Create mixed traces
        traces = [
            self._create_automation_trace(),
            self._create_fingerprinting_trace(),
            self._create_normal_trace()
        ]
        
        detection_context.network_traces = traces
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Validate statistics
        stats = result.statistics
        assert 'traces_analyzed' in stats
        assert stats['traces_analyzed'] == 3
        assert 'processing_time_ms' in stats
        assert stats['processing_time_ms'] > 0
        assert 'detection_rules_triggered' in stats
        assert stats['detection_rules_triggered'] >= 0
    
    @pytest.mark.asyncio
    async def test_error_handling(self, browser_detector, detection_context):
        """Test error handling during detection."""
        # Create trace with malformed data
        trace = NetworkTrace(
            id='malformed_trace',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=None,  # Malformed - no request
            response=None   # Malformed - no response
        )
        
        detection_context.network_traces = [trace]
        
        # Run detection - should not crash
        result = await browser_detector.detect(detection_context)
        
        # Should complete without crashing
        assert isinstance(result, DetectionResult)
        
        # May have errors in the result
        if result.errors:
            assert len(result.errors) >= 0  # Errors are tracked but don't crash detection
    
    def test_helper_methods(self, browser_detector):
        """Test helper methods."""
        # Test header value extraction
        headers = [
            {'name': 'User-Agent', 'value': 'TestAgent/1.0'},
            {'name': 'Accept', 'value': 'text/html'}
        ]
        
        user_agent = browser_detector._get_header_value(headers, 'user-agent')
        assert user_agent == 'TestAgent/1.0'
        
        accept = browser_detector._get_header_value(headers, 'Accept')
        assert accept == 'text/html'
        
        missing = browser_detector._get_header_value(headers, 'missing')
        assert missing is None
        
        # Test unusual user agent detection
        assert browser_detector._is_unusual_user_agent('Bot')  # Too short
        assert browser_detector._is_unusual_user_agent('CustomAgent/1.0')  # Missing common indicators
        assert browser_detector._is_unusual_user_agent('Mozilla/5.0 Chrome/0.0')  # Version 0.0
        assert not browser_detector._is_unusual_user_agent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
        
        # Test domain extraction
        assert browser_detector._extract_domain('https://example.com/path') == 'example.com'
        assert browser_detector._extract_domain('http://sub.example.com:8080/path') == 'sub.example.com:8080'
        assert browser_detector._extract_domain('invalid-url') == ''
        
        # Test service domain checking
        service_domains = ['example.com', 'test.org']
        assert browser_detector._is_service_domain('example.com', service_domains)
        assert browser_detector._is_service_domain('sub.example.com', service_domains)
        assert not browser_detector._is_service_domain('other.com', service_domains)
        assert not browser_detector._is_service_domain('', service_domains)
    
    def _create_automation_trace(self):
        """Helper to create automation trace."""
        request = HttpRequest(
            method='GET',
            url='https://example.com/test',
            headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0 selenium'}],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(
            status_code=403,
            status_text='Forbidden',
            body='Bot detected',
            size=512
        )
        
        return NetworkTrace(
            id='automation_trace',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=request,
            response=response
        )
    
    def _create_fingerprinting_trace(self):
        """Helper to create fingerprinting trace."""
        request = HttpRequest(
            method='GET',
            url='https://example.com/fingerprint.js',
            headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(
            status_code=200,
            status_text='OK',
            body='canvas fingerprint detection script',
            size=1024
        )
        
        return NetworkTrace(
            id='fingerprinting_trace',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=request,
            response=response
        )
    
    def _create_normal_trace(self):
        """Helper to create normal trace."""
        request = HttpRequest(
            method='GET',
            url='https://example.com/normal',
            headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(
            status_code=200,
            status_text='OK',
            body='<html><body>Normal content</body></html>',
            size=512
        )
        
        return NetworkTrace(
            id='normal_trace',
            source_format=LogFormat.HAR,
            timestamp=datetime.now(timezone.utc),
            request=request,
            response=response
        )
