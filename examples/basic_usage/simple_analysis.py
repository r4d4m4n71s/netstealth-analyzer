#!/usr/bin/env python3
"""
NetStealth Analyzer Example: Simple Analysis

Description: Basic example demonstrating how to analyze a HAR file for security issues.
This example shows the fundamental usage pattern of NetStealth Analyzer.

Requirements:
- NetStealth Analyzer v2.0+
- A HAR file to analyze

Usage:
    python simple_analysis.py
"""

import asyncio
import sys
from pathlib import Path
from netstealth_analyzer import NetStealthAnalyzer


async def simple_analysis_example():
    """
    Perform a basic security analysis on a HAR file.
    
    This example demonstrates:
    - Creating an analyzer with fluent API
    - Running basic analysis
    - Interpreting results
    - Generating a simple report
    """
    
    print("🔍 NetStealth Analyzer - Simple Analysis Example")
    print("=" * 50)
    
    # Check if sample file exists
    sample_file = Path("../sample_data/sample_session.har")
    if not sample_file.exists():
        print("⚠️  Sample HAR file not found. Creating a minimal example...")
        print("   In a real scenario, you would use your own HAR file.")
        print("   You can generate HAR files using browser developer tools.")
        return
    
    try:
        # Create analyzer with fluent API
        print("🔧 Creating analyzer...")
        analyzer = (NetStealthAnalyzer.create()
                    .with_logs(str(sample_file))
                    .for_service("example.com")
                    .build())
        
        print("✅ Analyzer created successfully")
        
        # Run analysis
        print("\n🚀 Starting analysis...")
        result = await analyzer.analyze()
        
        print("✅ Analysis completed!")
        
        # Display results
        print(f"\n📊 Analysis Results:")
        print(f"   Overall Score: {result.summary.overall_score}/100")
        print(f"   Analysis Duration: {result.summary.analysis_duration_ms}ms")
        print(f"   Issues Found: {len(result.issues)}")
        print(f"   Network Traces: {len(result.network_traces)}")
        
        # Show issues by severity
        if result.issues:
            print(f"\n🚨 Security Issues Found:")
            
            severity_counts = {}
            for issue in result.issues:
                severity = issue.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Display severity summary
            severity_icons = {
                'critical': '💥',
                'high': '🚨',
                'medium': '⚠️',
                'low': 'ℹ️',
                'info': '📝'
            }
            
            for severity, count in severity_counts.items():
                icon = severity_icons.get(severity, '❓')
                print(f"   {icon} {severity.title()}: {count}")
            
            # Show top 3 issues
            print(f"\n🔍 Top Issues:")
            for i, issue in enumerate(result.issues[:3], 1):
                print(f"   {i}. {issue.title}")
                print(f"      Severity: {issue.severity.value}")
                print(f"      Confidence: {issue.confidence:.1%}")
                print(f"      Category: {issue.category.value}")
                if issue.description:
                    print(f"      Description: {issue.description[:100]}...")
                print()
        
        else:
            print("✅ No security issues detected!")
        
        # Generate simple report
        print("📄 Generating JSON report...")
        from netstealth_analyzer.reporting.reporter import Report
        
        report = Report(analysis_result=result)
        report.save_json("simple_analysis_report.json")
        print("✅ Report saved to: simple_analysis_report.json")
        
        # Show network trace summary
        if result.network_traces:
            print(f"\n🌐 Network Analysis:")
            trace = result.network_traces[0]  # Show first trace as example
            print(f"   Sample Trace ID: {trace.trace_id}")
            print(f"   Number of Hops: {len(trace.hops)}")
            print(f"   Timestamp: {trace.timestamp}")
        
        # Cleanup
        await analyzer.shutdown()
        
        return result
        
    except FileNotFoundError as e:
        print(f"❌ File not found: {e}")
        print("💡 Make sure the HAR file exists and the path is correct")
        return None
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        print("💡 Check the troubleshooting guide for common solutions")
        return None


async def main():
    """Main function to run the example."""
    
    print("Starting NetStealth Analyzer simple analysis example...\n")
    
    # Run the analysis
    result = await simple_analysis_example()
    
    if result:
        print(f"\n✅ Example completed successfully!")
        print(f"   Final Score: {result.summary.overall_score}/100")
        
        # Provide next steps
        print(f"\n📚 Next Steps:")
        print(f"   1. Try the multiple_files.py example")
        print(f"   2. Explore streaming_analysis.py for large files")
        print(f"   3. Check the advanced_workflows/ directory")
        print(f"   4. Read the User Guide: ../docs/USER_GUIDE.md")
        
    else:
        print(f"\n❌ Example failed to complete")
        print(f"💡 Check the error messages above and refer to:")
        print(f"   - Troubleshooting Guide: ../docs/TROUBLESHOOTING.md")
        print(f"   - Sample Data: ../sample_data/README.md")


if __name__ == "__main__":
    # Run the example
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Analysis interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        print("💡 Please report this issue on GitHub")
        sys.exit(1)
