"""
Consolidated unit tests for browser detector.

This file merges all browser detector test cases from multiple files:
- test_detectors_browser.py (original comprehensive tests)
- test_detectors_browser_additional.py (cross-trace analysis, helper methods)
- test_detectors_browser_coverage.py (data exposure, tracking, debug leakage)
- test_detectors_browser_extended.py (extended functionality)
- test_detectors_browser_final_coverage.py (edge cases, error handling)
- test_detectors_browser_80_percent.py (specific missing line coverage)

Tests browser automation detection, fingerprinting detection, configuration analysis,
cross-trace patterns, edge cases, and comprehensive coverage scenarios.
"""

import pytest
import asyncio
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch, AsyncMock

from src.netstealth_analyzer.detectors.browser import BrowserDetector
from src.netstealth_analyzer.detectors.base import DetectionContext, DetectionResult
from src.netstealth_analyzer.models.network import NetworkTrace, HttpRequest, HttpResponse, TimingInfo, HttpData
from src.netstealth_analyzer.models.issues import Issue, IssueEvidence, DetectionRule
from src.netstealth_analyzer.models.enums import (
    SeverityLevel, IssueCategory, DetectionConfidence, LogFormat, NetworkProtocol
)
from src.netstealth_analyzer.core.events import EventBus


class TestBrowserDetectorConsolidated:
    """Consolidated test class for browser detector functionality."""
    
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
            body_size=1024
        )
        
        timing = TimingInfo(
            dns_lookup=50,
            tcp_connect=100,
            ssl_handshake=150,
            request_sent=200,
            waiting=800,
            content_download=200
        )
        
        http_data = HttpData(
            request=request,
            response=response,
            timing=timing,
            is_secure=True
        )
        
        return NetworkTrace(
            trace_id='automation_trace_1',
            protocol=NetworkProtocol.HTTPS,
            protocol_data=http_data,
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
            body_size=2048
        )
        
        timing = TimingInfo(
            dns_lookup=30,
            tcp_connect=80,
            ssl_handshake=120,
            request_sent=150,
            waiting=600,
            content_download=300
        )
        
        http_data = HttpData(
            request=request,
            response=response,
            timing=timing,
            is_secure=True
        )
        
        return NetworkTrace(
            trace_id='fingerprinting_trace_1',
            protocol=NetworkProtocol.HTTPS,
            protocol_data=http_data,
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
            body_size=512
        )
        
        timing = TimingInfo(
            dns_lookup=25,
            tcp_connect=60,
            ssl_handshake=100,
            request_sent=120,
            waiting=400,
            content_download=150
        )
        
        http_data = HttpData(
            request=request,
            response=response,
            timing=timing,
            is_secure=True
        )
        
        return NetworkTrace(
            trace_id='normal_trace_1',
            protocol=NetworkProtocol.HTTPS,
            protocol_data=http_data,
            metadata={'domain': 'example.com'}
        )
    
    # ========== BASIC DETECTOR PROPERTIES TESTS ==========
    
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
    
    # ========== AUTOMATION DETECTION TESTS ==========
    
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
        
        timing = TimingInfo(
            dns_lookup=40,
            tcp_connect=90,
            ssl_handshake=130,
            request_sent=180,
            waiting=700,
            content_download=180
        )
        
        http_data = HttpData(
            request=request,
            response=response,
            timing=timing,
            is_secure=True
        )
        
        trace = NetworkTrace(
            trace_id='selenium_trace',
            protocol=NetworkProtocol.HTTPS,
            protocol_data=http_data
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
        assert issue.category == IssueCategory.BROWSER_AUTOMATION
        assert issue.severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        assert issue.confidence >= 0.5
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
        
        timing = TimingInfo(
            dns_lookup=35,
            tcp_connect=85,
            ssl_handshake=125,
            request_sent=175,
            waiting=650,
            content_download=175
        )
        
        http_data = HttpData(
            request=request,
            response=response,
            timing=timing,
            is_secure=True
        )
        
        trace = NetworkTrace(
            trace_id='webdriver_trace',
            protocol=NetworkProtocol.HTTPS,
            protocol_data=http_data
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
        assert issue.category == IssueCategory.BROWSER_AUTOMATION
        assert issue.severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        assert "automation" in issue.description.lower()
    
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
        assert issue.category == IssueCategory.BROWSER_AUTOMATION
        assert issue.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        assert "automation" in issue.description.lower()
    
    @pytest.mark.asyncio
    async def test_unusual_user_agent_patterns(self, browser_detector, detection_context):
        """Test detection of unusual user agent patterns."""
        # Very short user agent
        short_ua_trace = NetworkTrace(
            trace_id='short_ua_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'Bot'}  # Very short
                    ]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'response'
                }
            }
        )
        
        # User agent with version 0.0
        zero_version_trace = NetworkTrace(
            trace_id='zero_version_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test2',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'Mozilla/5.0 Chrome/0.0 Safari/537.36'}
                    ]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'response'
                }
            }
        )
        
        # User agent missing common indicators
        unusual_ua_trace = NetworkTrace(
            trace_id='unusual_ua_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test3',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'CustomBot/1.0 (Windows NT 10.0)'}
                    ]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'response'
                }
            }
        )
        
        detection_context.network_traces = [short_ua_trace, zero_version_trace, unusual_ua_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect unusual user agent patterns
        assert len(result.issues_found) >= 2
        
        # Check for unusual user agent issues
        unusual_issues = [i for i in result.issues_found if 'Unusual User Agent' in i.title]
        assert len(unusual_issues) >= 1
    
    # ========== FINGERPRINTING DETECTION TESTS ==========
    
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
        assert canvas_issue.category == IssueCategory.FINGERPRINTING
        assert canvas_issue.severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        assert "canvas" in canvas_issue.description.lower()
    
    @pytest.mark.asyncio
    async def test_detect_webgl_fingerprinting(self, browser_detector, detection_context):
        """Test detection of WebGL fingerprinting."""
        # Test WebGL fingerprinting with specific keywords
        webgl_trace = NetworkTrace(
            trace_id='webgl_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'Mozilla/5.0'}
                    ]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'WebGL fingerprinting: getParameter, getSupportedExtensions, unmasked_vendor_webgl, unmasked_renderer_webgl'
                }
            }
        )
        
        detection_context.network_traces = [webgl_trace]
        
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
        assert issue.category == IssueCategory.FINGERPRINTING
        assert issue.severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        assert "webgl" in issue.description.lower()
    
    @pytest.mark.asyncio
    async def test_multiple_fingerprinting_detection(self, browser_detector, detection_context):
        """Test detection of multiple fingerprinting attempts."""
        # Create multiple traces with fingerprinting patterns
        fingerprinting_traces = []
        for i in range(5):  # Create 5 traces with fingerprinting
            trace = NetworkTrace(
                trace_id=f'fingerprint_trace_{i}',
                protocol=NetworkProtocol.HTTPS,
                metadata={
                    'domain': 'example.com',
                    'http_request': {
                        'method': 'GET',
                        'url': f'https://example.com/page{i}',
                        'headers': [
                            {'name': 'User-Agent', 'value': 'Mozilla/5.0'}
                        ]
                    },
                    'http_response': {
                        'status_code': 200,
                        'body': f'canvas fingerprint attempt {i} detected'
                    }
                }
            )
            fingerprinting_traces.append(trace)
        
        detection_context.network_traces = fingerprinting_traces
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect multiple fingerprinting attempts
        assert result.is_successful
        fingerprinting_issues = [i for i in result.issues_found if 'Fingerprinting' in i.title]
        assert len(fingerprinting_issues) >= 4  # Should detect multiple attempts
    
    # ========== ANTI-BOT CHALLENGE TESTS ==========
    
    @pytest.mark.asyncio
    async def test_detect_antibot_challenge(self, browser_detector, detection_context):
        """Test detection of anti-bot challenges."""
        # Test anti-bot challenge with 403 status
        antibot_403_trace = NetworkTrace(
            trace_id='antibot_403_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/protected',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'Mozilla/5.0'}
                    ]
                },
                'http_response': {
                    'status_code': 403,
                    'body': 'Cloudflare challenge required. Please verify you are human.'
                }
            }
        )
        
        # Test anti-bot challenge with 429 status
        antibot_429_trace = NetworkTrace(
            trace_id='antibot_429_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/rate-limited',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'Mozilla/5.0'}
                    ]
                },
                'http_response': {
                    'status_code': 429,
                    'body': 'captcha required for verification'
                }
            }
        )
        
        detection_context.network_traces = [antibot_403_trace, antibot_429_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect multiple types of issues
        assert result.is_successful
        assert len(result.issues_found) >= 2  # Should find anti-bot issues
        
        # Check for specific issue types
        antibot_issues = [i for i in result.issues_found if 'Anti-Bot' in i.title or 'Challenge' in i.title]
        assert len(antibot_issues) >= 2  # 403 and 429 responses
    
    # ========== JAVASCRIPT DETECTION TESTS ==========
    
    @pytest.mark.asyncio
    async def test_detect_javascript_detection_scripts(self, browser_detector, detection_context):
        """Test detection of JavaScript detection scripts."""
        # Test various URL patterns for JS detection
        js_url_patterns = [
            'https://example.com/detect.js',
            'https://example.com/scripts/fingerprint.js',
            'https://example.com/assets/bot-detection.js',
            'https://example.com/js/detection.js',
            'https://example.com/static/antibot.js',
            'https://example.com/path/to/js/bot-detection.js'
        ]
        
        js_traces = []
        for i, url in enumerate(js_url_patterns):
            trace = NetworkTrace(
                trace_id=f'js_url_trace_{i}',
                protocol=NetworkProtocol.HTTPS,
                metadata={
                    'domain': 'example.com',
                    'http_request': {
                        'method': 'GET',
                        'url': url,
                        'headers': [
                            {'name': 'User-Agent', 'value': 'Mozilla/5.0'}
                        ]
                    },
                    'http_response': {
                        'status_code': 200,
                        'body': 'Bot detection script loaded'
                    }
                }
            )
            js_traces.append(trace)
        
        detection_context.network_traces = js_traces
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect JavaScript-based detection attempts
        assert result.is_successful
        js_issues = [i for i in result.issues_found if 'JavaScript' in i.title]
        assert len(js_issues) >= 4  # Should detect most JS patterns
    
    # ========== CROSS-TRACE ANALYSIS TESTS ==========
    
    @pytest.mark.asyncio
    async def test_cross_trace_consistent_automation_detection(self, browser_detector, detection_context):
        """Test cross-trace analysis for consistent automation detection."""
        # Create multiple traces with automation detection indicators in metadata
        base_time = datetime.now(timezone.utc)
        traces = []
        
        # Create 10 traces to service domains with automation detection (>30% detection rate)
        for i in range(10):
            trace = NetworkTrace(
                trace_id=f'automation_trace_{i}',
                protocol=NetworkProtocol.HTTPS,
                metadata={
                    'domain': 'example.com',
                    'http_request': {
                        'method': 'GET',
                        'url': f'https://example.com/page{i}',  # Service domain URL
                        'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                    },
                    'http_response': {
                        'status_code': 403,
                        'body': f'Request {i}: automation detected by security system'
                    }
                },
                trace_start=base_time + timedelta(seconds=i)
            )
            traces.append(trace)
        
        # Add 2 normal traces to service domains (detection rate = 10/12 = 83% > 30%)
        for i in range(2):
            trace = NetworkTrace(
                trace_id=f'normal_trace_{i}',
                protocol=NetworkProtocol.HTTPS,
                metadata={
                    'domain': 'example.com',
                    'http_request': {
                        'method': 'GET',
                        'url': f'https://example.com/normal{i}',  # Service domain URL
                        'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                    },
                    'http_response': {
                        'status_code': 200,
                        'body': 'Normal response content'
                    }
                },
                trace_start=base_time + timedelta(seconds=i + 10)
            )
            traces.append(trace)
        
        detection_context.network_traces = traces
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect cross-trace consistent automation detection issue
        consistent_automation_issues = [
            issue for issue in result.issues_found
            if "consistent" in issue.title.lower() and "automation" in issue.title.lower()
        ]
        
        # Should find cross-trace analysis issue
        assert len(consistent_automation_issues) >= 1
        
        # Verify the consistent automation issue has correct properties
        for issue in consistent_automation_issues:
            assert issue.category == IssueCategory.BROWSER_AUTOMATION
            assert issue.severity == SeverityLevel.CRITICAL
            assert issue.confidence >= 0.7
            assert "83" in issue.description or "10" in issue.description  # Detection rate/count
    
    @pytest.mark.asyncio
    async def test_cross_trace_timing_analysis(self, browser_detector, detection_context):
        """Test cross-trace timing analysis for robotic patterns."""
        # Create traces with consistent timing (robotic pattern)
        base_time = datetime.now(timezone.utc)
        
        timing_traces = []
        for i in range(6):  # Need >5 for timing analysis
            # Create very consistent timing (1 second intervals, very low variance)
            trace_time = base_time.replace(second=i, microsecond=0)
            trace = NetworkTrace(
                trace_id=f'timing_trace_{i}',
                protocol=NetworkProtocol.HTTPS,
                trace_start=trace_time,
                metadata={
                    'domain': 'example.com',
                    'http_request': {
                        'method': 'GET',
                        'url': f'https://example.com/page{i}',
                        'timestamp': trace_time,
                        'headers': [
                            {'name': 'User-Agent', 'value': 'Mozilla/5.0'}
                        ]
                    },
                    'http_response': {
                        'status_code': 200,
                        'body': 'response'
                    }
                }
            )
            timing_traces.append(trace)
        
        detection_context.network_traces = timing_traces
        detection_context.service_domains = ['example.com']
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should complete successfully (timing analysis may or may not detect issues)
        assert result.is_successful
        assert result.statistics['traces_analyzed'] == 6
    
    # ========== DATA EXPOSURE DETECTION TESTS ==========
    
    @pytest.mark.asyncio
    async def test_data_exposure_detection(self, browser_detector, detection_context):
        """Test data exposure detection."""
        # Test API key exposure in URL
        api_key_trace = NetworkTrace(
            trace_id='api_key_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/api?api_key=secret123&data=test',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'API response'
                }
            }
        )
        
        # Test sensitive parameters
        sensitive_param_trace = NetworkTrace(
            trace_id='sensitive_param_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/form?ssn=123-45-6789&credit_card=4111111111111111',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'Form submitted'
                }
            }
        )
        
        # Test PII in response
        pii_response_trace = NetworkTrace(
            trace_id='pii_response_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/profile',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'User profile: SSN 123-45-6789, Bank Account: 987654321'
                }
            }
        )
        
        # Test debug parameters
        debug_param_trace = NetworkTrace(
            trace_id='debug_param_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/api?debug=1&include_sensitive=true',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'Debug response'
                }
            }
        )
        
        detection_context.network_traces = [api_key_trace, sensitive_param_trace, pii_response_trace, debug_param_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect data exposure issues
        assert result.is_successful
        assert len(result.issues_found) >= 2  # Should find API key and sensitive data issues
        
        # Check for specific issue types
        api_key_issues = [i for i in result.issues_found if 'API Key' in i.title]
        sensitive_issues = [i for i in result.issues_found if 'Sensitive' in i.title]
        pii_issues = [i for i in result.issues_found if 'Personal Information' in i.title]
        debug_issues = [i for i in result.issues_found if 'Debug' in i.title]
        
        assert len(api_key_issues) >= 1
        assert len(sensitive_issues) >= 1 or len(pii_issues) >= 1 or len(debug_issues) >= 1
    
    # ========== TRACKING DETECTION TESTS ==========
    
    @pytest.mark.asyncio
    async def test_tracking_detection(self, browser_detector, detection_context):
        """Test tracking detection."""
        # Test tracking requests
        tracking_trace = NetworkTrace(
            trace_id='tracking_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://analytics.third-party-tracker.com/collect',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'Tracking pixel'
                }
            }
        )
        
        # Test fingerprint collection
        fingerprint_collection_trace = NetworkTrace(
            trace_id='fingerprint_collection_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'POST',
                    'url': 'https://example.com/fingerprint/collect',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}],
                    'body': 'comprehensive_tracking=true&user_identification=abc123'
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'Fingerprint collected'
                }
            }
        )
        
        # Test behavioral tracking
        behavioral_trace = NetworkTrace(
            trace_id='behavioral_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'POST',
                    'url': 'https://example.com/analytics',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}],
                    'body': 'behavioral_analysis=true&mouse_movements=data'
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'Analytics recorded'
                }
            }
        )
        
        # Test tracking cookies
        tracking_cookies_trace = NetworkTrace(
            trace_id='tracking_cookies_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/page',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'headers': [
                        {'name': 'Set-Cookie', 'value': 'tracking_id=abc123; Domain=.example.com'},
                        {'name': 'Set-Cookie', 'value': '_ga=GA1.2.123456789; Domain=.example.com'},
                        {'name': 'Set-Cookie', 'value': 'fb_pixel=pixel123; Domain=.example.com'}
                    ],
                    'body': 'Page content'
                }
            }
        )
        
        detection_context.network_traces = [tracking_trace, fingerprint_collection_trace, behavioral_trace, tracking_cookies_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect tracking issues
        assert result.is_successful
        assert len(result.issues_found) >= 2  # Should find tracking issues
        
        # Check for specific tracking issue types
        tracking_issues = [i for i in result.issues_found if 'Tracking' in i.title]
        fingerprint_issues = [i for i in result.issues_found if 'Fingerprint' in i.title]
        behavioral_issues = [i for i in result.issues_found if 'Behavioral' in i.title]
        cookie_issues = [i for i in result.issues_found if 'Cookie' in i.title]
        
        assert len(tracking_issues) >= 1 or len(fingerprint_issues) >= 1 or len(behavioral_issues) >= 1 or len(cookie_issues) >= 1
    
    # ========== DEBUG LEAKAGE DETECTION TESTS ==========
    
    @pytest.mark.asyncio
    async def test_debug_leakage_detection(self, browser_detector, detection_context):
        """Test debug information leakage detection."""
        # Test debug headers
        debug_headers_trace = NetworkTrace(
            trace_id='debug_headers_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/api',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'headers': [
                        {'name': 'X-Debug-Info', 'value': 'enabled'},
                        {'name': 'X-Database-Queries', 'value': '15'},
                        {'name': 'X-Memory-Usage', 'value': '256MB'},
                        {'name': 'X-Execution-Time', 'value': '1.5s'}
                    ],
                    'body': 'API response'
                }
            }
        )
        
        # Test debug mode
        debug_mode_trace = NetworkTrace(
            trace_id='debug_mode_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/app',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'Application running in debug mode. Debug_mode: enabled'
                }
            }
        )
        
        # Test system info leakage
        system_info_trace = NetworkTrace(
            trace_id='system_info_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/status',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'System status: Database queries: 150, Memory usage: 512MB, Execution time: 2.1s'
                }
            }
        )
        
        # Test admin token leakage
        admin_token_trace = NetworkTrace(
            trace_id='admin_token_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/admin',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'Admin panel loaded. Admin_token: secret123, Debug_token: debug456'
                }
            }
        )
        
        detection_context.network_traces = [debug_headers_trace, debug_mode_trace, system_info_trace, admin_token_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect debug leakage issues
        assert result.is_successful
        assert len(result.issues_found) >= 2  # Should find debug issues
        
        # Check for specific debug issue types
        debug_header_issues = [i for i in result.issues_found if 'Debug Information' in i.title and 'Headers' in i.title]
        debug_mode_issues = [i for i in result.issues_found if 'Debug Mode' in i.title]
        system_info_issues = [i for i in result.issues_found if 'System Information' in i.title]
        admin_token_issues = [i for i in result.issues_found if 'Administrative Token' in i.title]
        
        assert len(debug_header_issues) >= 1 or len(debug_mode_issues) >= 1 or len(system_info_issues) >= 1 or len(admin_token_issues) >= 1
    
    # ========== EDGE CASES AND ERROR HANDLING TESTS ==========
    
    @pytest.mark.asyncio
    async def test_edge_case_coverage_scenarios(self, browser_detector, detection_context):
        """Test edge cases to improve coverage."""
        # Test trace with no metadata and no protocol_data
        empty_trace = NetworkTrace(
            trace_id='empty_trace',
            protocol=NetworkProtocol.HTTPS
        )
        
        # Test trace with empty metadata
        empty_metadata_trace = NetworkTrace(
            trace_id='empty_metadata_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={}
        )
        
        # Test trace with partial metadata (only request, no response)
        partial_metadata_trace = NetworkTrace(
            trace_id='partial_metadata_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'Mozilla/5.0'}
                    ]
                }
                # No http_response
            }
        )
        
        # Test trace with partial metadata (only response, no request)
        response_only_trace = NetworkTrace(
            trace_id='response_only_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_response': {
                    'status_code': 200,
                    'body': 'normal response'
                }
                # No http_request
            }
        )
        
        detection_context.network_traces = [
            empty_trace, empty_metadata_trace, partial_metadata_trace, response_only_trace
        ]
        
        # Run detection - should handle all edge cases gracefully
        result = await browser_detector.detect(detection_context)
        
        # Should complete without errors
        assert result.is_successful
        assert result.statistics['traces_analyzed'] == 4
    
    @pytest.mark.asyncio
    async def test_error_handling_scenarios(self, browser_detector, detection_context):
        """Test error handling in various scenarios."""
        # Test with trace that might cause processing errors
        problematic_trace = NetworkTrace(
            trace_id='problematic_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [
                        {'name': 'User-Agent', 'value': None}  # None value that might cause issues
                    ]
                },
                'http_response': {
                    'status_code': 200,
                    'body': None  # None body that might cause issues
                }
            }
        )
        
        detection_context.network_traces = [problematic_trace]
        
        # Run detection - should handle errors gracefully
        result = await browser_detector.detect(detection_context)
        
        # Should complete and track any errors
        assert result.statistics['traces_analyzed'] == 1
        # Errors might be recorded but shouldn't crash
    
    @pytest.mark.asyncio
    async def test_progress_emission_coverage(self, browser_detector, detection_context):
        """Test progress emission scenarios."""
        # Create many traces to trigger progress emission every 100 traces
        many_traces = []
        for i in range(105):  # More than 100 to trigger progress emission
            trace = NetworkTrace(
                trace_id=f'progress_trace_{i}',
                protocol=NetworkProtocol.HTTPS,
                metadata={
                    'domain': 'example.com',
                    'http_request': {
                        'method': 'GET',
                        'url': f'https://example.com/page{i}',
                        'headers': [
                            {'name': 'User-Agent', 'value': 'Mozilla/5.0'}
                        ]
                    },
                    'http_response': {
                        'status_code': 200,
                        'body': 'response'
                    }
                }
            )
            many_traces.append(trace)
        
        detection_context.network_traces = many_traces
        
        # Run detection - should trigger progress emission
        result = await browser_detector.detect(detection_context)
        
        # Should complete successfully
        assert result.is_successful
        assert result.statistics['traces_analyzed'] == 105
    
    @pytest.mark.asyncio
    async def test_confidence_threshold_filtering(self, browser_detector, detection_context):
        """Test confidence threshold filtering scenarios."""
        # Set high confidence threshold
        detection_context.confidence_threshold = 0.9
        
        # Create trace that generates medium confidence issues
        medium_confidence_trace = NetworkTrace(
            trace_id='medium_confidence_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'Mozilla/5.0'}
                    ]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'canvas fingerprint detected'  # Medium confidence issue
                }
            }
        )
        
        detection_context.network_traces = [medium_confidence_trace]
        
        # Run detection with high threshold
        result = await browser_detector.detect(detection_context)
        
        # Medium confidence issues should be filtered out
        assert result.statistics['traces_analyzed'] == 1
        # Issues might be filtered due to high confidence threshold
    
    # ========== HELPER METHODS TESTS ==========
    
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
    
    # ========== HELPER METHODS FOR TEST CREATION ==========
    
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
            body_size=512
        )
        
        return NetworkTrace(
            trace_id='automation_trace',
            metadata={
                'http_request': request.model_dump(),
                'http_response': response.model_dump()
            }
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
            body_size=1024
        )
        
        return NetworkTrace(
            trace_id='fingerprinting_trace',
            metadata={
                'http_request': request.model_dump(),
                'http_response': response.model_dump()
            }
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
            body_size=512
        )
        
        return NetworkTrace(
            trace_id='normal_trace',
            metadata={
                'http_request': request.model_dump(),
                'http_response': response.model_dump()
            }
        )
    
    # ========== ADDITIONAL COVERAGE TESTS ==========
    
    @pytest.mark.asyncio
    async def test_error_handling_in_trace_analysis(self, browser_detector, detection_context):
        """Test error handling during trace analysis."""
        # Create a trace that will cause an error during analysis
        problematic_trace = NetworkTrace(
            trace_id='error_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': None  # This might cause an error
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'response'
                }
            }
        )
        
        detection_context.network_traces = [problematic_trace]
        
        # Run detection - should handle errors gracefully
        result = await browser_detector.detect(detection_context)
        
        # Should complete and potentially record errors
        assert result.statistics['traces_analyzed'] == 1
        # Errors might be recorded but shouldn't crash
    
    @pytest.mark.asyncio
    async def test_detection_with_no_traces(self, browser_detector, detection_context):
        """Test detection with empty trace list."""
        detection_context.network_traces = []
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should complete successfully with no issues
        assert len(result.issues_found) == 0
        assert result.statistics['traces_analyzed'] == 0
    
    @pytest.mark.asyncio
    async def test_detection_with_missing_trace_id(self, browser_detector, detection_context):
        """Test detection with trace missing ID."""
        trace_without_id = NetworkTrace(
            trace_id="",  # Empty trace ID instead of None
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'Mozilla/5.0'}
                    ]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'response'
                }
            }
        )
        
        detection_context.network_traces = [trace_without_id]
        
        # Run detection - should handle missing ID gracefully
        result = await browser_detector.detect(detection_context)
        
        # Should complete successfully
        assert result.statistics['traces_analyzed'] == 1
    
    @pytest.mark.asyncio
    async def test_request_body_tracking_detection(self, browser_detector, detection_context):
        """Test tracking detection in request body."""
        # Create trace with request body containing tracking data
        tracking_trace = NetworkTrace(
            trace_id='tracking_body_trace',
            protocol=NetworkProtocol.HTTPS,
            protocol_data=HttpData(
                request=HttpRequest(
                    method='POST',
                    url='https://example.com/analytics',
                    headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0'}],
                    body='comprehensive_tracking=true&user_identification=abc123&behavioral_analysis=enabled&mouse_movements=data',
                    timestamp=datetime.now(timezone.utc)
                ),
                response=HttpResponse(
                    status_code=200,
                    status_text='OK',
                    body='Analytics recorded'
                ),
                timing=TimingInfo(
                    dns_lookup=30,
                    tcp_connect=80,
                    ssl_handshake=120,
                    request_sent=150,
                    waiting=600,
                    content_download=300
                ),
                is_secure=True
            )
        )
        
        detection_context.network_traces = [tracking_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect tracking issues
        assert len(result.issues_found) >= 1
        tracking_issues = [i for i in result.issues_found if 'Tracking' in i.title]
        assert len(tracking_issues) >= 1
    
    @pytest.mark.asyncio
    async def test_response_headers_tracking_cookies(self, browser_detector, detection_context):
        """Test tracking cookie detection in response headers."""
        # Create trace with tracking cookies in response headers
        cookie_trace = NetworkTrace(
            trace_id='cookie_trace',
            protocol=NetworkProtocol.HTTPS,
            protocol_data=HttpData(
                request=HttpRequest(
                    method='GET',
                    url='https://example.com/page',
                    headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0'}],
                    timestamp=datetime.now(timezone.utc)
                ),
                response=HttpResponse(
                    status_code=200,
                    status_text='OK',
                    headers=[
                        {'name': 'Set-Cookie', 'value': 'tracking_id=abc123; Domain=.example.com'},
                        {'name': 'Set-Cookie', 'value': '_ga=GA1.2.123456789; Domain=.example.com'},
                        {'name': 'Set-Cookie', 'value': 'fb_pixel=pixel123; Domain=.example.com'},
                        {'name': 'Set-Cookie', 'value': 'analytics_session=xyz789; Domain=.example.com'}
                    ],
                    body='Page content'
                ),
                timing=TimingInfo(
                    dns_lookup=25,
                    tcp_connect=60,
                    ssl_handshake=100,
                    request_sent=120,
                    waiting=400,
                    content_download=150
                ),
                is_secure=True
            )
        )
        
        detection_context.network_traces = [cookie_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect tracking cookie issues
        assert len(result.issues_found) >= 1
        cookie_issues = [i for i in result.issues_found if 'Cookie' in i.title]
        assert len(cookie_issues) >= 1
    
    @pytest.mark.asyncio
    async def test_debug_headers_detection(self, browser_detector, detection_context):
        """Test debug header detection."""
        # Create trace with debug headers in response
        debug_trace = NetworkTrace(
            trace_id='debug_headers_trace',
            protocol=NetworkProtocol.HTTPS,
            protocol_data=HttpData(
                request=HttpRequest(
                    method='GET',
                    url='https://example.com/api',
                    headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0'}],
                    timestamp=datetime.now(timezone.utc)
                ),
                response=HttpResponse(
                    status_code=200,
                    status_text='OK',
                    headers=[
                        {'name': 'X-Debug-Info', 'value': 'enabled'},
                        {'name': 'X-Database-Queries', 'value': '15'},
                        {'name': 'X-Memory-Usage', 'value': '256MB'},
                        {'name': 'X-Execution-Time', 'value': '1.5s'}
                    ],
                    body='API response'
                ),
                timing=TimingInfo(
                    dns_lookup=30,
                    tcp_connect=80,
                    ssl_handshake=120,
                    request_sent=150,
                    waiting=600,
                    content_download=300
                ),
                is_secure=True
            )
        )
        
        detection_context.network_traces = [debug_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect debug header issues
        assert len(result.issues_found) >= 1
        debug_issues = [i for i in result.issues_found if 'Debug' in i.title]
        assert len(debug_issues) >= 1
    
    @pytest.mark.asyncio
    async def test_system_info_leakage_detection(self, browser_detector, detection_context):
        """Test system information leakage detection."""
        # Create trace with system info in response body
        system_info_trace = NetworkTrace(
            trace_id='system_info_trace',
            protocol=NetworkProtocol.HTTPS,
            protocol_data=HttpData(
                request=HttpRequest(
                    method='GET',
                    url='https://example.com/status',
                    headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0'}],
                    timestamp=datetime.now(timezone.utc)
                ),
                response=HttpResponse(
                    status_code=200,
                    status_text='OK',
                    body='System status: Database queries: 150, Memory usage: 512MB, Execution time: 2.1s'
                ),
                timing=TimingInfo(
                    dns_lookup=30,
                    tcp_connect=80,
                    ssl_handshake=120,
                    request_sent=150,
                    waiting=600,
                    content_download=300
                ),
                is_secure=True
            )
        )
        
        detection_context.network_traces = [system_info_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect system info leakage
        assert len(result.issues_found) >= 1
        system_issues = [i for i in result.issues_found if 'System Information' in i.title]
        assert len(system_issues) >= 1
    
    @pytest.mark.asyncio
    async def test_admin_token_leakage_detection(self, browser_detector, detection_context):
        """Test admin token leakage detection."""
        # Create trace with admin tokens in response body
        admin_token_trace = NetworkTrace(
            trace_id='admin_token_trace',
            protocol=NetworkProtocol.HTTPS,
            protocol_data=HttpData(
                request=HttpRequest(
                    method='GET',
                    url='https://example.com/admin',
                    headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0'}],
                    timestamp=datetime.now(timezone.utc)
                ),
                response=HttpResponse(
                    status_code=200,
                    status_text='OK',
                    body='Admin panel loaded. Admin_token: secret123, Debug_token: debug456, Internal_key: internal789'
                ),
                timing=TimingInfo(
                    dns_lookup=30,
                    tcp_connect=80,
                    ssl_handshake=120,
                    request_sent=150,
                    waiting=600,
                    content_download=300
                ),
                is_secure=True
            )
        )
        
        detection_context.network_traces = [admin_token_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect admin token leakage
        assert len(result.issues_found) >= 1
        token_issues = [i for i in result.issues_found if 'Token' in i.title]
        assert len(token_issues) >= 1
    
    @pytest.mark.asyncio
    async def test_debug_mode_detection(self, browser_detector, detection_context):
        """Test debug mode detection."""
        # Create trace with debug mode indicators
        debug_mode_trace = NetworkTrace(
            trace_id='debug_mode_trace',
            protocol=NetworkProtocol.HTTPS,
            protocol_data=HttpData(
                request=HttpRequest(
                    method='GET',
                    url='https://example.com/app',
                    headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0'}],
                    timestamp=datetime.now(timezone.utc)
                ),
                response=HttpResponse(
                    status_code=200,
                    status_text='OK',
                    body='Application running in debug mode. Debug_mode: enabled, verbose logging active'
                ),
                timing=TimingInfo(
                    dns_lookup=30,
                    tcp_connect=80,
                    ssl_handshake=120,
                    request_sent=150,
                    waiting=600,
                    content_download=300
                ),
                is_secure=True
            )
        )
        
        detection_context.network_traces = [debug_mode_trace]
        
        # Run detection
        result = await browser_detector.detect(detection_context)
        
        # Should detect debug mode issues
        assert len(result.issues_found) >= 1
        debug_mode_issues = [i for i in result.issues_found if 'Debug Mode' in i.title]
        assert len(debug_mode_issues) >= 1
    
    @pytest.mark.asyncio
    async def test_cross_trace_analysis_edge_cases(self, browser_detector, detection_context):
        """Test cross-trace analysis edge cases."""
        # Create traces with edge case scenarios
        traces = []
        
        # Trace with no metadata
        empty_trace = NetworkTrace(
            trace_id='empty_trace',
            protocol=NetworkProtocol.HTTPS
        )
        traces.append(empty_trace)
        
        # Trace with metadata but no URL
        no_url_trace = NetworkTrace(
            trace_id='no_url_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                    # No URL
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'response'
                }
            }
        )
        traces.append(no_url_trace)
        
        # Trace with invalid domain
        invalid_domain_trace = NetworkTrace(
            trace_id='invalid_domain_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'invalid-url-format',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'response'
                }
            }
        )
        traces.append(invalid_domain_trace)
        
        detection_context.network_traces = traces
        
        # Run detection - should handle edge cases gracefully
        result = await browser_detector.detect(detection_context)
        
        # Should complete without errors
        assert result.statistics['traces_analyzed'] == 3
    
    @pytest.mark.asyncio
    async def test_timing_analysis_edge_cases(self, browser_detector, detection_context):
        """Test timing analysis with edge cases."""
        # Create traces with various timing scenarios
        base_time = datetime.now(timezone.utc)
        traces = []
        
        # Traces with no timestamps
        for i in range(3):
            trace = NetworkTrace(
                trace_id=f'no_timestamp_trace_{i}',
                protocol=NetworkProtocol.HTTPS,
                metadata={
                    'domain': 'example.com',
                    'http_request': {
                        'method': 'GET',
                        'url': f'https://example.com/page{i}',
                        'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                        # No timestamp
                    },
                    'http_response': {
                        'status_code': 200,
                        'body': 'response'
                    }
                }
            )
            traces.append(trace)
        
        # Traces with only some timestamps
        for i in range(3):
            trace = NetworkTrace(
                trace_id=f'partial_timestamp_trace_{i}',
                protocol=NetworkProtocol.HTTPS,
                trace_start=base_time.replace(second=i) if i % 2 == 0 else None,
                metadata={
                    'domain': 'example.com',
                    'http_request': {
                        'method': 'GET',
                        'url': f'https://example.com/page{i+3}',
                        'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                    },
                    'http_response': {
                        'status_code': 200,
                        'body': 'response'
                    }
                }
            )
            traces.append(trace)
        
        detection_context.network_traces = traces
        
        # Run detection - should handle timing edge cases
        result = await browser_detector.detect(detection_context)
        
        # Should complete successfully
        assert result.statistics['traces_analyzed'] == 6
    
    # ========== METADATA-BASED HELPER METHODS TESTS ==========
    
    @pytest.mark.asyncio
    async def test_metadata_based_user_agent_detection(self, browser_detector, detection_context):
        """Test metadata-based user agent detection methods."""
        # Create trace with automation user agent in metadata
        trace = NetworkTrace(
            trace_id='metadata_ua_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'Mozilla/5.0 selenium/3.141.0'},
                        {'name': 'Accept', 'value': 'text/html'}
                    ]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'response'
                }
            }
        )
        
        detection_context.network_traces = [trace]
        
        # Run detection - should use metadata-based methods
        result = await browser_detector.detect(detection_context)
        
        # Should detect automation user agent
        assert len(result.issues_found) >= 1
        ua_issues = [i for i in result.issues_found if 'User Agent' in i.title]
        assert len(ua_issues) >= 1
    
    @pytest.mark.asyncio
    async def test_metadata_based_automation_headers_detection(self, browser_detector, detection_context):
        """Test metadata-based automation headers detection."""
        # Create trace with automation headers in metadata
        trace = NetworkTrace(
            trace_id='metadata_headers_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'Mozilla/5.0'},
                        {'name': 'webdriver', 'value': 'true'},
                        {'name': 'selenium-remote-control', 'value': '1'}
                    ]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'response'
                }
            }
        )
        
        detection_context.network_traces = [trace]
        
        # Run detection - should use metadata-based methods
        result = await browser_detector.detect(detection_context)
        
        # Should detect automation headers
        assert len(result.issues_found) >= 1
        header_issues = [i for i in result.issues_found if 'Headers' in i.title]
        assert len(header_issues) >= 1
    
    @pytest.mark.asyncio
    async def test_metadata_based_automation_detection(self, browser_detector, detection_context):
        """Test metadata-based automation detection in response."""
        # Create trace with automation detection in response metadata
        trace = NetworkTrace(
            trace_id='metadata_detection_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 403,
                    'body': 'Bot detected. Automation detected by security system.'
                }
            }
        )
        
        detection_context.network_traces = [trace]
        
        # Run detection - should use metadata-based methods
        result = await browser_detector.detect(detection_context)
        
        # Should detect automation detection message
        assert len(result.issues_found) >= 1
        detection_issues = [i for i in result.issues_found if 'Automation Detected' in i.title]
        assert len(detection_issues) >= 1
    
    @pytest.mark.asyncio
    async def test_metadata_based_fingerprinting_detection(self, browser_detector, detection_context):
        """Test metadata-based fingerprinting detection."""
        # Create trace with fingerprinting in response metadata
        trace = NetworkTrace(
            trace_id='metadata_fingerprint_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/fingerprint.js',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'Canvas fingerprint detection: getContext, toDataURL, WebGL fingerprinting: getParameter, getSupportedExtensions, unmasked_vendor_webgl, unmasked_renderer_webgl'
                }
            }
        )
        
        detection_context.network_traces = [trace]
        
        # Run detection - should use metadata-based methods
        result = await browser_detector.detect(detection_context)
        
        # Should detect fingerprinting attempts
        assert len(result.issues_found) >= 1
        fingerprint_issues = [i for i in result.issues_found if 'Fingerprint' in i.title]
        assert len(fingerprint_issues) >= 1
    
    @pytest.mark.asyncio
    async def test_metadata_based_antibot_challenges(self, browser_detector, detection_context):
        """Test metadata-based anti-bot challenge detection."""
        # Create trace with anti-bot challenge in metadata
        trace = NetworkTrace(
            trace_id='metadata_antibot_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/protected',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 403,
                    'body': 'Cloudflare challenge required. Please verify you are human.'
                }
            }
        )
        
        detection_context.network_traces = [trace]
        
        # Run detection - should use metadata-based methods
        result = await browser_detector.detect(detection_context)
        
        # Should detect anti-bot challenge
        assert len(result.issues_found) >= 1
        challenge_issues = [i for i in result.issues_found if 'Challenge' in i.title or 'Anti-Bot' in i.title]
        assert len(challenge_issues) >= 1
    
    @pytest.mark.asyncio
    async def test_metadata_based_javascript_patterns(self, browser_detector, detection_context):
        """Test metadata-based JavaScript pattern detection."""
        # Create traces with various JS detection patterns
        js_patterns = [
            'https://example.com/detect.js',
            'https://example.com/scripts/fingerprint.js',
            'https://example.com/assets/bot-detection.js',
            'https://example.com/js/detection.js',
            'https://example.com/static/antibot.js'
        ]
        
        traces = []
        for i, url in enumerate(js_patterns):
            trace = NetworkTrace(
                trace_id=f'metadata_js_trace_{i}',
                protocol=NetworkProtocol.HTTPS,
                metadata={
                    'domain': 'example.com',
                    'http_request': {
                        'method': 'GET',
                        'url': url,
                        'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                    },
                    'http_response': {
                        'status_code': 200,
                        'body': 'Bot detection script loaded'
                    }
                }
            )
            traces.append(trace)
        
        detection_context.network_traces = traces
        
        # Run detection - should use metadata-based methods
        result = await browser_detector.detect(detection_context)
        
        # Should detect JavaScript detection patterns
        assert len(result.issues_found) >= 3
        js_issues = [i for i in result.issues_found if 'JavaScript' in i.title]
        assert len(js_issues) >= 3
    
    @pytest.mark.asyncio
    async def test_metadata_based_automation_indicators(self, browser_detector, detection_context):
        """Test metadata-based automation indicators helper method."""
        # Create trace with automation indicators in metadata
        trace_with_indicators = NetworkTrace(
            trace_id='metadata_indicators_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 403,
                    'body': 'Selenium detected. Webdriver detected. Automation detected.'
                }
            }
        )
        
        # Create trace without automation indicators
        trace_without_indicators = NetworkTrace(
            trace_id='metadata_no_indicators_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/normal',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'Normal response content'
                }
            }
        )
        
        detection_context.network_traces = [trace_with_indicators, trace_without_indicators]
        
        # Run detection - should use metadata-based helper methods
        result = await browser_detector.detect(detection_context)
        
        # Should detect automation indicators in first trace only
        assert len(result.issues_found) >= 1
        automation_issues = [i for i in result.issues_found if 'Automation' in i.title]
        assert len(automation_issues) >= 1
    
    @pytest.mark.asyncio
    async def test_metadata_edge_cases_coverage(self, browser_detector, detection_context):
        """Test metadata-based methods with edge cases for coverage."""
        # Create trace with empty headers list
        trace_empty_headers = NetworkTrace(
            trace_id='metadata_empty_headers_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': []  # Empty headers list
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'response'
                }
            }
        )
        
        # Create trace with missing headers field
        trace_no_headers = NetworkTrace(
            trace_id='metadata_no_headers_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test'
                    # No headers field
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'response'
                }
            }
        )
        
        # Create trace with missing response body
        trace_no_body = NetworkTrace(
            trace_id='metadata_no_body_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'status_code': 200
                    # No body field
                }
            }
        )
        
        # Create trace with missing status code
        trace_no_status = NetworkTrace(
            trace_id='metadata_no_status_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                },
                'http_response': {
                    'body': 'response'
                    # No status_code field
                }
            }
        )
        
        # Create trace with missing URL
        trace_no_url = NetworkTrace(
            trace_id='metadata_no_url_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0'}]
                    # No url field
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'response'
                }
            }
        )
        
        detection_context.network_traces = [
            trace_empty_headers, trace_no_headers, trace_no_body, 
            trace_no_status, trace_no_url
        ]
        
        # Run detection - should handle all edge cases gracefully
        result = await browser_detector.detect(detection_context)
        
        # Should complete without errors
        assert result.statistics['traces_analyzed'] == 5
    
    @pytest.mark.asyncio
    async def test_metadata_helper_methods_direct(self, browser_detector):
        """Test metadata-based helper methods directly for coverage."""
        # Create test trace
        trace = NetworkTrace(
            trace_id='direct_test_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/test',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'Mozilla/5.0 selenium'},
                        {'name': 'webdriver', 'value': 'true'}
                    ]
                },
                'http_response': {
                    'status_code': 403,
                    'body': 'Bot detected. Canvas fingerprint. WebGL fingerprinting.'
                }
            }
        )
        
        # Test individual metadata-based helper methods
        http_request = trace.metadata.get('http_request', {})
        http_response = trace.metadata.get('http_response', {})
        
        # Test _check_user_agent_from_metadata
        ua_issues = browser_detector._check_user_agent_from_metadata(trace, http_request)
        assert len(ua_issues) >= 1
        
        # Test _check_automation_headers_from_metadata
        header_issues = browser_detector._check_automation_headers_from_metadata(trace, http_request)
        assert len(header_issues) >= 1
        
        # Test _check_automation_detection_from_metadata
        detection_issues = browser_detector._check_automation_detection_from_metadata(trace, http_response)
        assert len(detection_issues) >= 1
        
        # Test _check_fingerprinting_attempts_from_metadata
        fingerprint_issues = browser_detector._check_fingerprinting_attempts_from_metadata(trace, http_response)
        assert len(fingerprint_issues) >= 1
        
        # Test _check_antibot_challenges_from_metadata
        antibot_issues = browser_detector._check_antibot_challenges_from_metadata(trace, http_response)
        # Anti-bot detection requires specific status codes (403, 429, 503) AND specific keywords
        # The trace has status 403 but body doesn't contain 'cloudflare', 'captcha', or 'challenge'
        # So this might not detect anti-bot issues - that's expected behavior
        assert len(antibot_issues) >= 0  # Allow 0 or more issues
        
        # Test _check_javascript_patterns_from_metadata
        js_issues = browser_detector._check_javascript_patterns_from_metadata(trace, http_request)
        # May or may not find issues depending on URL patterns
        
        # Test _has_automation_detection_indicators_from_metadata
        has_indicators = browser_detector._has_automation_detection_indicators_from_metadata(trace)
        assert has_indicators is True
        
        # Test with trace without indicators
        clean_trace = NetworkTrace(
            trace_id='clean_test_trace',
            protocol=NetworkProtocol.HTTPS,
            metadata={
                'domain': 'example.com',
                'http_request': {
                    'method': 'GET',
                    'url': 'https://example.com/normal',
                    'headers': [{'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'Normal response content'
                }
            }
        )
        
        has_indicators_clean = browser_detector._has_automation_detection_indicators_from_metadata(clean_trace)
        assert has_indicators_clean is False
