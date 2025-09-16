#!/usr/bin/env python
"""
Enhanced NetStealth log analysis with validation and clear error reporting.

This example demonstrates:
1. Dependency checking before analysis
2. Log validation with detailed feedback
3. Graceful degradation for missing/incomplete logs
4. Clear user guidance on analysis limitations
"""

import sys
from pathlib import Path
from datetime import datetime

# Add analyzer to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from netstealth_analyzer.dependency_check import check_netstealth_dependencies
from netstealth_analyzer.validators.log_validator import NetStealthLogValidator
from netstealth_analyzer.models import AnalysisConfig, TargetGeography
from netstealth_analyzer.parsers.poc import PocExecutionParser
from netstealth_analyzer.parsers.har import HarParser
from netstealth_analyzer.detectors.proxy import ProxyDetector

def verify_environment():
    """Check dependencies and provide clear feedback."""
    print("🔍 Verifying NetStealth Analysis Environment...")
    print("-" * 50)
    
    try:
        check_netstealth_dependencies()
        print("✅ All dependencies are available")
        return True
    except ImportError as e:
        print(e)
        print("\n💡 Fix dependencies and run again")
        return False

def analyze_netstealth_logs():
    """Enhanced analysis with validation and clear feedback."""
    
    # Step 1: Environment check
    if not verify_environment():
        return 1
    
    # Step 2: Find most recent logs directory
    logs_base_dir = Path("../netstealth/logs")
    
    if not logs_base_dir.exists():
        print(f"\n❌ Logs base directory not found: {logs_base_dir}")
        print("💡 Run NetStealth complete_workflow.py example first to generate logs")
        return 1
    
    # Find the most recent integrated workflow directory
    workflow_dirs = list(logs_base_dir.glob("*_integrated_workflow"))
    
    if not workflow_dirs:
        print(f"\n❌ No integrated workflow logs found in: {logs_base_dir}")
        print("💡 Run NetStealth complete_workflow.py example first to generate logs")
        return 1
    
    # Sort by creation time and get the most recent
    logs_dir = max(workflow_dirs, key=lambda p: p.stat().st_mtime)
    
    print(f"\n📁 Found most recent logs directory: {logs_dir}")
    print(f"   Created: {datetime.fromtimestamp(logs_dir.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Step 3: Validate log completeness
    print(f"\n🔍 Validating NetStealth logs...")
    validator = NetStealthLogValidator()
    validation_results = validator.validate_netstealth_logs(logs_dir)
    
    # Display validation report
    validation_report = validator.generate_validation_report(validation_results)
    print(validation_report)
    
    # Check analysis readiness
    readiness, confidence = validator.get_analysis_readiness(validation_results)
    critical_issues = validator.get_critical_issues(validation_results)
    
    if critical_issues:
        print(f"\n🚨 Critical Issues Preventing Analysis:")
        for issue in critical_issues:
            print(f"  • {issue}")
        print(f"\n💡 Fix NetStealth log generation and run again")
        return 1
    
    # Step 4: Configure analysis
    target_geo = TargetGeography(
        country_code="US",
        country_name="United States", 
        ip_ranges=["203.0.113.0/24"],
        timezone="America/New_York",
        language="en-US"
    )
    
    config = AnalysisConfig(
        service_domains=[
            "example.com",
            "httpbin.org"
        ],
        target_geography=target_geo
    )
    
    # Step 5: Run analysis with degraded mode handling
    print(f"\n📊 Running Analysis (Mode: {readiness}, Confidence: {confidence:.1%})")
    print("=" * 60)
    
    analysis_results = {
        "validation": {
            "readiness": readiness,
            "confidence": confidence,
            "results": validation_results
        },
        "parsed_sources": [],
        "proxy_issues": [],
        "summary": {}
    }
    
    # Parse available logs
    sources_parsed = 0
    
    # Parse POC execution log
    poc_log = logs_dir / "poc_execution.log"
    poc_result = validation_results["poc_execution"]
    if poc_result.status.value in ["complete", "incomplete"]:
        print("  🔍 Parsing POC execution log...")
        try:
            poc_parser = PocExecutionParser(config)
            poc_data = poc_parser.parse(poc_log)
            analysis_results["parsed_sources"].append({
                "format": "poc_execution",
                "path": str(poc_log),
                "data": poc_data,
                "quality": poc_result.status.value
            })
            health_score = poc_data.get("statistics", {}).get("session_health_score", 85.0)
            print(f"    ✅ POC: {health_score:.1f}/100 health score")
            sources_parsed += 1
        except Exception as e:
            print(f"    ❌ POC parsing error: {e}")
    else:
        print(f"  ❌ POC log not available for analysis")
    
    # Parse HAR log
    har_log = logs_dir / "network_trace.har"
    har_result = validation_results["network_trace"]
    if har_result.status.value in ["complete", "incomplete"]:
        print("  🌐 Parsing network trace (HAR)...")
        try:
            har_parser = HarParser(config)
            har_data = har_parser.parse(har_log)
            analysis_results["parsed_sources"].append({
                "format": "har",
                "path": str(har_log),
                "data": har_data,
                "quality": har_result.status.value
            })
            success_rate = har_data.get("statistics", {}).get("success_rate", 95.0)
            print(f"    ✅ HAR: {success_rate:.1f}% success rate")
            sources_parsed += 1
        except Exception as e:
            print(f"    ❌ HAR parsing error: {e}")
    else:
        print(f"  ❌ HAR log not available for analysis")
    
    # Run proxy detection if we have sources
    if analysis_results["parsed_sources"]:
        print("  🛡️  Running proxy detection analysis...")
        try:
            proxy_detector = ProxyDetector(config)
            parsed_data = {"sources": analysis_results["parsed_sources"]}
            proxy_issues = proxy_detector.detect(parsed_data)
            
            analysis_results["proxy_issues"] = [
                {
                    "id": issue.id,
                    "title": issue.title,
                    "severity": issue.severity.value,
                    "impact_score": issue.impact_score,
                    "description": issue.description[:200] + "..." if len(issue.description) > 200 else issue.description,
                    "recommendation": issue.recommendation
                } for issue in proxy_issues
            ]
            print(f"    🚨 Found {len(proxy_issues)} proxy-related issues")
        except Exception as e:
            print(f"    ❌ Proxy detection error: {e}")
    
    # Generate summary
    analysis_results["summary"] = {
        "sources_parsed": sources_parsed,
        "sources_expected": len(validator.EXPECTED_LOGS),
        "proxy_issues_found": len(analysis_results["proxy_issues"]),
        "critical_issues": len([i for i in analysis_results["proxy_issues"] if i["severity"] == "CRITICAL"]),
        "high_issues": len([i for i in analysis_results["proxy_issues"] if i["severity"] == "HIGH"]),
        "analysis_confidence": confidence,
        "analysis_mode": readiness
    }
    
    # Step 6: Display results with context
    print(f"\n📊 Analysis Results Summary")
    print("=" * 60)
    summary = analysis_results["summary"]
    
    print(f"🎯 Analysis Completeness: {summary['sources_parsed']}/{summary['sources_expected']} sources parsed ({confidence:.1%})")
    print(f"🔍 Analysis Mode: {readiness}")
    print(f"🚨 Security Issues: {summary['proxy_issues_found']} total")
    print(f"   • Critical: {summary['critical_issues']}")
    print(f"   • High Priority: {summary['high_issues']}")
    
    if analysis_results["proxy_issues"]:
        print(f"\n🛡️  Security Issues Detected:")
        for issue in analysis_results["proxy_issues"][:3]:  # Show first 3
            print(f"  • {issue['title']} (Impact: {issue['impact_score']}/100)")
            print(f"    {issue['description']}")
            if issue['recommendation']:
                print(f"    💡 Fix: {issue['recommendation']}")
            print()
    
    # Analysis limitations based on missing logs
    limitations = []
    for log_type, result in validation_results.items():
        if result.status.value in ["missing", "corrupted"]:
            limitations.append(result.impact)
    
    if limitations:
        print(f"⚠️  Analysis Limitations (due to missing/corrupted logs):")
        for limitation in limitations:
            print(f"  • {limitation}")
    
    print(f"\n📈 Confidence Assessment:")
    if confidence >= 0.8:
        print(f"  ✅ HIGH CONFIDENCE - Analysis results are reliable")
    elif confidence >= 0.5:
        print(f"  ⚠️  MODERATE CONFIDENCE - Some analysis features limited")
    else:
        print(f"  ❌ LOW CONFIDENCE - Analysis severely limited by missing data")
    
    print(f"\n💡 Next Steps:")
    if confidence < 1.0:
        print(f"  • Fix NetStealth log generation for complete analysis")
        print(f"  • Re-run NetStealth examples to generate missing logs")
    print(f"  • Review security issues and apply recommendations")
    print(f"  • Monitor proxy configuration for detected vulnerabilities")
    
    return 0

def main():
    """Run enhanced NetStealth log analysis."""
    print("🌟 Enhanced NetStealth Log Analysis")
    print("=" * 60)
    print("Features: Validation • Clear Error Reporting • Graceful Degradation")
    print("")
    
    try:
        return analyze_netstealth_logs()
    except KeyboardInterrupt:
        print("\n⏸️ Analysis interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
