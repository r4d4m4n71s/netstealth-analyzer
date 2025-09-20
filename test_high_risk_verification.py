#!/usr/bin/env python3
"""
Test script to verify sample_high_risk_session.har performs as expected.
This will analyze the file and compare results against documented expectations.
"""

import sys
import os
import json
import asyncio
from datetime import datetime

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from netstealth_analyzer import NetStealthAnalyzer

async def test_high_risk_session():
    """Test the high-risk session HAR file for expected security issues."""
    
    print("🔍 Testing sample_high_risk_session.har")
    print("=" * 60)
    
    # Initialize analyzer with comprehensive detection
    print("🔧 Building analyzer...")
    builder = NetStealthAnalyzer.create()
    builder = builder.with_logs("examples/sample_data/sample_high_risk_session.har")
    print(f"📁 Log files added: {len(builder._log_files)}")
    
    builder = builder.with_detectors("proxy", "browser", "network", "tls")
    print(f"🔍 Detectors added via builder: {len(builder._detectors)}")
    
    analyzer = builder.build()
    print(f"🏗️ Built analyzer with {len(analyzer._detectors)} detectors")
    
    # Print detector names for debugging
    for i, detector in enumerate(analyzer._detectors):
        print(f"   Detector {i+1}: {type(detector).__name__} - {detector.name}")
    
    # Run analysis
    print("⚙️ Running analysis...")
    try:
        results = await analyzer.analyze()
    except Exception as e:
        print(f"❌ Analysis failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print(f"\n📊 Analysis Results:")
    print(f"   Overall Score: {results.summary.overall_score}/100")
    print(f"   Risk Level: {results.summary.overall_risk_level}")
    print(f"   Total Issues: {len(results.issues)}")
    
    # Count issues by severity
    critical_count = len([i for i in results.issues if str(i.severity).lower() == "critical"])
    high_count = len([i for i in results.issues if str(i.severity).lower() == "high"])
    medium_count = len([i for i in results.issues if str(i.severity).lower() == "medium"])
    low_count = len([i for i in results.issues if str(i.severity).lower() == "low"])
    
    print(f"   Critical Issues: {critical_count}")
    print(f"   High Issues: {high_count}")
    print(f"   Medium Issues: {medium_count}")
    print(f"   Low Issues: {low_count}")
    
    # Expected vs Actual comparison
    print(f"\n🎯 Expected vs Actual:")
    print(f"   Expected Score: 5-20/100")
    print(f"   Actual Score: {results.summary.overall_score}/100")
    print(f"   Expected Risk: critical")
    print(f"   Actual Risk: {results.summary.overall_risk_level}")
    print(f"   Expected Issues: 15-25+")
    print(f"   Actual Issues: {len(results.issues)}")
    
    # Detailed issue breakdown
    print(f"\n🔍 Detected Issues:")
    for i, issue in enumerate(results.issues, 1):
        severity_str = str(issue.severity).upper()
        category_str = str(issue.category)
        print(f"   {i:2d}. [{severity_str:8s}] {category_str} - {issue.description}")
        if hasattr(issue, 'context') and issue.context:
            print(f"       Context: {issue.context}")
    
    # Performance test expectations
    print(f"\n✅ Validation Results:")
    
    # Score validation
    score_ok = 5 <= results.summary.overall_score <= 20
    print(f"   Score Range (5-20): {'✅ PASS' if score_ok else '❌ FAIL'} ({results.summary.overall_score})")
    
    # Risk level validation  
    risk_ok = results.summary.overall_risk_level == "critical"
    print(f"   Risk Level (critical): {'✅ PASS' if risk_ok else '❌ FAIL'} ({results.summary.overall_risk_level})")
    
    # Issue count validation
    issue_count_ok = len(results.issues) >= 15
    print(f"   Issue Count (15+): {'✅ PASS' if issue_count_ok else '❌ FAIL'} ({len(results.issues)})")
    
    # Critical issue validation
    critical_ok = critical_count >= 5
    print(f"   Critical Issues (5+): {'✅ PASS' if critical_ok else '❌ FAIL'} ({critical_count})")
    
    # Security categories expected
    categories_found = set(str(issue.category) for issue in results.issues)
    expected_categories = {
        "browser_automation", "proxy_detection", "ip_leakage", 
        "data_exposure", "fingerprinting", "tracking", "debug_leakage"
    }
    
    categories_ok = len(categories_found.intersection(expected_categories)) >= 5
    print(f"   Security Categories (5+): {'✅ PASS' if categories_ok else '❌ FAIL'} ({len(categories_found.intersection(expected_categories))})")
    
    # Overall test result
    all_tests_pass = all([score_ok, risk_ok, issue_count_ok, critical_ok, categories_ok])
    
    print(f"\n🎉 Overall Test Result: {'✅ PASS' if all_tests_pass else '❌ FAIL'}")
    
    if all_tests_pass:
        print("   The sample_high_risk_session.har is performing as expected!")
        print("   All security issues are being detected correctly.")
    else:
        print("   ⚠️ Issues found with detection performance:")
        if not score_ok:
            print(f"      - Score {results.summary.overall_score} outside expected range 5-20")
        if not risk_ok:
            print(f"      - Risk level {results.summary.overall_risk_level} should be critical")
        if not issue_count_ok:
            print(f"      - Only {len(results.issues)} issues found, expected 15+")
        if not critical_ok:
            print(f"      - Only {critical_count} critical issues found, expected 5+")
        if not categories_ok:
            print(f"      - Only {len(categories_found.intersection(expected_categories))} security categories detected")
    
    # Generate detailed report
    report_file = f"high_risk_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    report_data = {
        "test_timestamp": datetime.now().isoformat(),
        "test_file": "examples/sample_data/sample_high_risk_session.har",
        "results": {
            "overall_score": results.summary.overall_score,
            "risk_level": results.summary.overall_risk_level,
            "total_issues": len(results.issues),
            "critical_issues": critical_count,
            "high_issues": high_count,
            "medium_issues": medium_count,
            "low_issues": low_count
        },
        "validation": {
            "score_range_5_20": score_ok,
            "risk_level_critical": risk_ok,
            "issue_count_15_plus": issue_count_ok,
            "critical_issues_5_plus": critical_ok,
            "security_categories_5_plus": categories_ok,
            "overall_pass": all_tests_pass
        },
        "detected_categories": list(categories_found),
        "expected_categories": list(expected_categories),
        "issues": [
            {
                "severity": str(issue.severity),
                "category": str(issue.category),
                "description": issue.description,
                "context": getattr(issue, 'context', None)
            }
            for issue in results.issues
        ]
    }
    
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2)
    
    print(f"\n📄 Detailed report saved: {report_file}")
    
    return all_tests_pass

if __name__ == "__main__":
    try:
        success = asyncio.run(test_high_risk_session())
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
