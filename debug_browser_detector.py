#!/usr/bin/env python3
"""Debug script to test browser detector behavior."""

import asyncio
from datetime import datetime, timezone, timedelta
from src.netstealth_analyzer.detectors.browser import BrowserDetector
from src.netstealth_analyzer.detectors.base import DetectionContext
from src.netstealth_analyzer.models.network import NetworkTrace, HttpRequest, HttpResponse, TimingInfo, HttpData
from src.netstealth_analyzer.models.enums import NetworkProtocol
from src.netstealth_analyzer.core.events import EventBus


async def test_debug():
    event_bus = EventBus()
    detector = BrowserDetector(event_bus=event_bus, confidence_threshold=0.7)
    
    # Test trace with suspicious user agent
    trace = NetworkTrace(
        trace_id='test_trace',
        protocol=NetworkProtocol.HTTPS,
        protocol_data=HttpData(
            request=HttpRequest(
                method='GET',
                url='https://example.com/test',
                headers=[{'name': 'User-Agent', 'value': 'Mozilla/5.0 selenium webdriver'}],
                timestamp=datetime.now(timezone.utc)
            ),
            response=HttpResponse(
                status_code=403,
                status_text='Forbidden',
                headers=[],
                body='automation detected by security system',
                body_size=50
            ),
            timing=TimingInfo(
                dns_lookup=30,
                tcp_connect=80,
                ssl_handshake=120,
                request_sent=150,
                waiting=600,
                content_download=200
            ),
            is_secure=True
        ),
        metadata={'domain': 'example.com'}
    )
    
    context = DetectionContext(
        network_traces=[trace],
        service_domains=['example.com'],
        confidence_threshold=0.7
    )
    
    result = await detector.detect(context)
    print(f'Issues found: {len(result.issues_found)}')
    for issue in result.issues_found:
        print(f'- {issue.title} (confidence: {issue.confidence})')
        # The rule_id is now in raw_data field
        rule_id = issue.raw_data.get('rule_id', 'No rule_id') if issue.raw_data else 'No raw_data'
        print(f'  Rule ID: {rule_id}')
        print(f'  Category: {issue.category}')
        print(f'  Severity: {issue.severity}')
        print(f'  Raw Data: {issue.raw_data}')
    print(f'Rules applied: {len(result.detection_rules_applied)}')
    for rule in result.detection_rules_applied:
        print(f'- {rule.id}: {rule.name}')


if __name__ == '__main__':
    asyncio.run(test_debug())
