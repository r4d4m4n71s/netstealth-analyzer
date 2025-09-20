#!/usr/bin/env python3
"""
Debug script to understand TLS detection issues.
"""

import asyncio
from unittest.mock import Mock
from netstealth_analyzer.detectors.tls import TlsDetector
from netstealth_analyzer.detectors.base import DetectionContext
from netstealth_analyzer.models.network import NetworkTrace, TLSInfo, ConnectionInfo
from netstealth_analyzer.models.enums import TLSVersion

async def debug_certificate_detection():
    """Debug certificate issue detection."""
    print("=== Debugging Certificate Detection ===")
    
    # Create detector
    detector = TlsDetector()
    
    # Create mock TLS info with certificate issues
    tls_info = TLSInfo(
        version=TLSVersion.TLS_12,
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        certificate_issues=["expired"]  # This should trigger detection
    )
    
    print(f"TLS Info created: {tls_info}")
    print(f"Certificate issues: {tls_info.certificate_issues}")
    print(f"Has certificate_issues attr: {hasattr(tls_info, 'certificate_issues')}")
    print(f"Certificate issues is truthy: {bool(tls_info.certificate_issues)}")
    
    # Create mock network trace
    trace = Mock(spec=NetworkTrace)
    trace.trace_id = "test-trace-123"
    
    # Create connection info with TLS info
    connection_info = Mock(spec=ConnectionInfo)
    connection_info.tls_info = tls_info
    trace.connection_info = connection_info
    
    print(f"Trace connection_info: {trace.connection_info}")
    print(f"Trace TLS info: {trace.connection_info.tls_info}")
    
    # Create detection context
    context = DetectionContext(
        network_traces=[trace],
        service_domains=["example.com"],
        confidence_threshold=0.7
    )
    
    # Run detection
    result = await detector.detect(context)
    
    print(f"Detection result: {result}")
    print(f"Issues found: {len(result.issues_found)}")
    for issue in result.issues_found:
        print(f"  - {issue.title}: {issue.description}")
    
    return result

async def debug_fingerprinting_risk():
    """Debug fingerprinting risk assessment."""
    print("\n=== Debugging Fingerprinting Risk ===")
    
    # Create detector
    detector = TlsDetector()
    
    # Create TLS info with automation cipher
    tls_info = TLSInfo(
        version=TLSVersion.TLS_12,
        cipher_suite="selenium_automation_cipher",  # Should trigger fingerprinting risk
        extensions=["ext_1", "ext_2"],  # Few extensions (should trigger)
        handshake_duration_ms=5  # Very fast (should trigger)
    )
    
    print(f"TLS Info: {tls_info}")
    print(f"Cipher suite: {tls_info.cipher_suite}")
    print(f"Extensions: {tls_info.extensions}")
    print(f"Handshake duration: {tls_info.handshake_duration_ms}")
    
    # Test risk assessment directly
    risk_score = detector._assess_fingerprinting_risk(tls_info)
    print(f"Risk score: {risk_score}")
    
    # Test automation signature detection
    automation_detected = detector._detect_automation_signature(tls_info)
    print(f"Automation detected: {automation_detected}")
    
    # Create mock network trace
    trace = Mock(spec=NetworkTrace)
    trace.trace_id = "test-trace-456"
    
    connection_info = Mock(spec=ConnectionInfo)
    connection_info.tls_info = tls_info
    trace.connection_info = connection_info
    
    # Create detection context
    context = DetectionContext(
        network_traces=[trace],
        service_domains=["example.com"],
        confidence_threshold=0.7
    )
    
    # Run detection
    result = await detector.detect(context)
    
    print(f"Issues found: {len(result.issues_found)}")
    for issue in result.issues_found:
        print(f"  - {issue.title}: {issue.description}")
    
    return result

async def main():
    """Main debug function."""
    await debug_certificate_detection()
    await debug_fingerprinting_risk()

if __name__ == "__main__":
    asyncio.run(main())
