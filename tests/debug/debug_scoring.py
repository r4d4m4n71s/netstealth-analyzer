#!/usr/bin/env python3
"""
Debug script to trace scoring calculation in NetStealth Analyzer.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from netstealth_analyzer.builder import AnalyzerBuilder


async def debug_scoring():
    """Debug the scoring calculation step by step."""
    print("🔍 Debugging NetStealth Analyzer Scoring")
    print("=" * 60)
    
    # Build analyzer
    builder = AnalyzerBuilder()
    analyzer = (builder
                .with_log("examples/sample_data/sample_high_risk_session.har")
                .for_service("example.com")
                .build())
    
    print(f"🏗️ Built analyzer with {len(analyzer._detectors)} detectors")
    for i, detector in enumerate(analyzer._detectors, 1):
        print(f"   Detector {i}: {type(detector).__name__} - {getattr(detector, 'name', 'Unknown')}")
    
    # Run analysis
    print("\n⚙️ Running analysis...")
    result = await analyzer.analyze()
    
    print(f"\n📊 Analysis Results:")
    print(f"   Overall Score: {result.summary.overall_score}/100")
    print(f"   Total Issues: {len(result.issues)}")
    
    # Debug scoring calculation
    print(f"\n🔍 Debugging Scoring Calculation:")
    
    # Count issues by severity
    severity_counts = {}
    for i, issue in enumerate(result.issues):
        severity_key = str(issue.severity).lower()
        if hasattr(issue.severity, 'value'):
            severity_key = issue.severity.value.lower()
        
        severity_counts[severity_key] = severity_counts.get(severity_key, 0) + 1
        if i < 5:  # Only show first 5 issues to avoid spam
            print(f"   Issue {i+1}: {issue.category} - Severity: {severity_key} (type: {type(issue.severity)})")
    
    if len(result.issues) > 5:
        print(f"   ... and {len(result.issues) - 5} more issues")
    
    print(f"\n📈 Severity Counts:")
    for severity, count in severity_counts.items():
        print(f"   {severity}: {count}")
    
    # Manual scoring calculation
    print(f"\n🧮 Manual Scoring Calculation:")
    manual_score = 100
    total_deductions = 0
    
    for severity, count in severity_counts.items():
        if severity == 'critical':
            deduction = count * 3
            manual_score -= deduction
            total_deductions += deduction
            print(f"   Critical: {count} × 3 = -{deduction}")
        elif severity == 'high':
            deduction = count * 2
            manual_score -= deduction
            total_deductions += deduction
            print(f"   High: {count} × 2 = -{deduction}")
        elif severity == 'medium':
            deduction = count * 1
            manual_score -= deduction
            total_deductions += deduction
            print(f"   Medium: {count} × 1 = -{deduction}")
        elif severity == 'low':
            deduction = count * 0.5
            manual_score -= deduction
            total_deductions += deduction
            print(f"   Low: {count} × 0.5 = -{deduction}")
    
    manual_score = max(0, int(manual_score))
    
    print(f"\n📊 Scoring Summary:")
    print(f"   Starting Score: 100")
    print(f"   Total Deductions: -{total_deductions}")
    print(f"   Manual Calculated Score: {manual_score}")
    print(f"   Actual Result Score: {result.summary.overall_score}")
    print(f"   Match: {'✅' if manual_score == result.summary.overall_score else '❌'}")
    
    # Check if score is in expected range
    expected_min, expected_max = 5, 20
    in_range = expected_min <= result.summary.overall_score <= expected_max
    print(f"\n🎯 Expected Range Check:")
    print(f"   Expected: {expected_min}-{expected_max}")
    print(f"   Actual: {result.summary.overall_score}")
    print(f"   In Range: {'✅' if in_range else '❌'}")


if __name__ == "__main__":
    asyncio.run(debug_scoring())
