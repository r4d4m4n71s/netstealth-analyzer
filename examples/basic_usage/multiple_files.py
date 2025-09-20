#!/usr/bin/env python3
"""
NetStealth Analyzer Example: Multiple File Analysis

Description: Demonstrates analyzing multiple log files of different formats together.
This example shows how to process HAR files and proxy logs simultaneously for
comprehensive security analysis across different data sources.

Requirements:
- NetStealth Analyzer v2.0+
- Multiple log files (HAR, proxy logs, etc.)

Usage:
    python multiple_files.py
"""

import asyncio
import sys
from pathlib import Path
from typing import Dict, List, Any
from netstealth_analyzer import NetStealthAnalyzer
from netstealth_analyzer.core.events import AnalysisEvent


async def analyze_multiple_files():
    """
    Demonstrate multi-file analysis with different log formats.
    
    This example shows how to:
    - Analyze multiple files simultaneously
    - Handle different log formats
    - Correlate findings across data sources
    - Generate comprehensive reports
    """
    
    print("🔍 NetStealth Analyzer - Multiple File Analysis Example")
    print("=" * 55)
    
    # Define log files to analyze
    log_files = [
        "../sample_data/sample_session.har",    # Browser HAR file
        "../sample_data/sample_proxy.log"       # Proxy log file
    ]
    
    # Validate files exist
    missing_files = []
    for log_file in log_files:
        if not Path(log_file).exists():
            missing_files.append(log_file)
    
    if missing_files:
        print("❌ Missing log files:")
        for file in missing_files:
            print(f"   - {file}")
        print("💡 Make sure sample data exists in ../sample_data/")
        return
    
    print(f"📁 Analyzing {len(log_files)} log files:")
    for log_file in log_files:
        file_path = Path(log_file)
        size_kb = file_path.stat().st_size / 1024
        print(f"   ✅ {file_path.name} ({size_kb:.1f} KB)")
    
    try:
        # Event handlers for progress tracking
        async def on_analysis_started(event, data):
            components = data.get('components_count', 0)
            print(f"\n🚀 Analysis started with {components} components")
        
        async def on_progress_update(event, data):
            if hasattr(data, 'percentage'):
                percentage = data.percentage
                message = data.message if hasattr(data, 'message') else 'Processing...'
                print(f"📊 Progress: {percentage:.1f}% - {message}")
        
        async def on_issue_found(event, data):
            severity_icons = {
                'critical': '💥', 'high': '🚨', 
                'medium': '⚠️', 'low': 'ℹ️'
            }
            icon = severity_icons.get(data.severity, '❓')
            print(f"   {icon} Found: {data.title} ({data.severity})")
        
        async def on_analysis_completed(event, data):
            duration = data.get('duration_ms', 0)
            issues_count = data.get('issues_count', 0)
            print(f"✅ Analysis completed: {issues_count} issues found ({duration}ms)")
        
        # Create analyzer with multiple files
        print("\n🔧 Configuring multi-file analyzer...")
        analyzer = (NetStealthAnalyzer.create()
                    .with_logs(*log_files)  # Pass multiple files
                    .for_service("example.com")  # Target service
                    .with_detectors("proxy", "browser", "network")  # Multiple detectors
                    .on(AnalysisEvent.ANALYSIS_STARTED, on_analysis_started)
                    .on(AnalysisEvent.PROGRESS_UPDATE, on_progress_update)
                    .on(AnalysisEvent.ISSUE_FOUND, on_issue_found)
                    .on(AnalysisEvent.ANALYSIS_COMPLETED, on_analysis_completed)
                    .build())
        
        print("✅ Multi-file analyzer configured")
        
        # Run analysis
        print("\n🔍 Starting multi-file security analysis...")
        result = await analyzer.analyze()
        
        # Process and display results
        print(f"\n📊 Multi-File Analysis Results:")
        print(f"   Overall Score: {result.summary.overall_score}/100")
        print(f"   Total Issues: {len(result.issues)}")
        print(f"   Network Traces: {len(result.network_traces)}")
        print(f"   Analysis Duration: {result.summary.analysis_duration_ms}ms")
        
        # Categorize issues by source and type
        if result.issues:
            print(f"\n🔍 Issue Analysis:")
            
            # Group by severity
            severity_groups = {}
            for issue in result.issues:
                severity = issue.severity.value
                if severity not in severity_groups:
                    severity_groups[severity] = []
                severity_groups[severity].append(issue)
            
            for severity, issues in severity_groups.items():
                print(f"\n   {severity.upper()} Issues ({len(issues)}):")
                for issue in issues[:3]:  # Show top 3 per severity
                    print(f"   • {issue.title}")
                    print(f"     Category: {issue.category.value}")
                    print(f"     Confidence: {issue.confidence:.1%}")
        
        # Analyze cross-file correlations
        print(f"\n🔗 Cross-File Analysis:")
        har_traces = []
        proxy_traces = []
        
        for trace in result.network_traces:
            # Simple heuristic: traces with detailed HTTP metadata likely from HAR
            if trace.metadata and len(trace.metadata) > 3:
                har_traces.append(trace)
            else:
                proxy_traces.append(trace)
        
        print(f"   HAR-derived traces: {len(har_traces)}")
        print(f"   Proxy-derived traces: {len(proxy_traces)}")
        print(f"   Total unique traces: {len(result.network_traces)}")
        
        # Generate reports
        print(f"\n📄 Generating comprehensive reports...")
        
        from netstealth_analyzer.reporting.reporter import Report
        
        report = Report(analysis_result=result)
        
        # Save multiple format reports
        timestamp = result.execution_context.start_time.strftime("%Y%m%d_%H%M%S")
        
        json_file = f"multi_file_analysis_{timestamp}.json"
        html_file = f"multi_file_analysis_{timestamp}.html"
        
        report.save_json(json_file)
        report.save_html(html_file)
        
        print(f"   ✅ JSON report: {json_file}")
        print(f"   ✅ HTML report: {html_file}")
        
        # Recommendations
        print(f"\n💡 Multi-File Analysis Benefits:")
        print(f"   • Cross-validation of findings across data sources")
        print(f"   • Complete picture from browser and proxy perspectives")
        print(f"   • Enhanced detection through data correlation")
        print(f"   • Reduced false positives through multi-source verification")
        
        # Cleanup
        await analyzer.shutdown()
        
        return result
        
    except Exception as e:
        print(f"❌ Multi-file analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return None


async def main():
    """Main function to run the multi-file analysis example."""
    
    print("NetStealth Analyzer v2.0 - Python 3.13+")
    print("Starting multi-file analysis example...\n")
    
    try:
        result = await analyze_multiple_files()
        
        if result:
            print(f"\n🎉 Multi-file analysis completed successfully!")
            print(f"   Files Analyzed: 2")
            print(f"   Issues Found: {len(result.issues)}")
            print(f"   Network Traces: {len(result.network_traces)}")
            print(f"   Overall Score: {result.summary.overall_score}/100")
            
            print(f"\n📚 What You Learned:")
            print(f"   • How to analyze multiple files simultaneously")
            print(f"   • Cross-file issue correlation techniques")
            print(f"   • Multi-format log processing")
            print(f"   • Comprehensive security analysis workflows")
            
        else:
            print(f"\n❌ Multi-file analysis failed to complete")
            print(f"💡 Check the error messages above and ensure:")
            print(f"   - Sample data files exist in ../sample_data/")
            print(f"   - NetStealth Analyzer is properly installed")
            print(f"   - You're running from the examples/basic_usage directory")
            
    except KeyboardInterrupt:
        print(f"\n⏹️  Analysis interrupted by user")
        
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
