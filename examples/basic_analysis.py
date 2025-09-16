"""
Basic usage example for NetStealth Analyzer.

This example demonstrates how to use the NetStealth Analyzer to analyze
log files and detect stealth operation issues.
"""

import logging
from pathlib import Path
from netstealth-analyzer import NetStealthAnalyzer

def main():
    """Demonstrate basic NetStealth Analyzer functionality."""
    print("🔍 NetStealth Analyzer - Basic Analysis Example")
    print("=" * 55)
    
    # Initialize analyzer with default configuration
    analyzer = NetStealthAnalyzer()
    
    print("✅ Analyzer initialized with default configuration")
    
    # Example with custom configuration
    custom_config = {
        'auto_remediation': True,
        'fingerprint_comparison': False,  # Disabled for this example
        'session_timeline': True,
        'max_issues_per_category': 5
    }
    
    analyzer_custom = NetStealthAnalyzer(config=custom_config)
    print(f"\nCustom analyzer configured with remediation enabled")
    
    # Simulate analyzing log files (these files would need to exist for real analysis)
    sample_logs = [
        'logs/mitmproxy_session.log',
        'logs/browser_console.log', 
        'logs/network_trace.har'
    ]
    
    print(f"\n📋 Would analyze the following log sources:")
    for log_file in sample_logs:
        status = "✅ Found" if Path(log_file).exists() else "❌ Not found"
        print(f"  • {log_file} - {status}")
    
    # Example of analyzing existing sample data
    # Note: In real usage, you'd have actual log files
    print(f"\n🔬 Analysis Configuration:")
    print(f"  • Auto-remediation: {custom_config['auto_remediation']}")
    print(f"  • Session timeline: {custom_config['session_timeline']}")
    print(f"  • Max issues per category: {custom_config['max_issues_per_category']}")
    
    # Show example of what analysis results would look like
    print(f"\n📊 Example Analysis Results:")
    print(f"  • Overall Score: 85/100")
    print(f"  • Status: PARTIAL_SUCCESS")
    print(f"  • Critical Issues: 0")
    print(f"  • High Issues: 2") 
    print(f"  • Medium Issues: 3")
    print(f"  • Total Issues: 5")
    
    print(f"\n🛡️  Example Detected Issues:")
    print(f"  • TLS Fingerprint: Consistent cipher suite usage ✅")
    print(f"  • Proxy Headers: Minor X-Forwarded-For exposure ⚠️")
    print(f"  • Browser Config: Clean automation signatures ✅")
    print(f"  • Network Anomalies: Standard response patterns ✅")
    
    print(f"\n🔧 Example Auto-Remediation Suggestions:")
    print(f"  • Remove X-Forwarded-For headers in proxy configuration")
    print(f"  • Update User-Agent rotation frequency")
    print(f"  • Optimize request timing patterns")
    
    print(f"\n🌐 Example Network Trace:")
    print(f"  1. Client → Local Proxy (127.0.0.1:8080)")
    print(f"  2. Local Proxy → Upstream Proxy (geo.proxy.com)")
    print(f"  3. Upstream Proxy → Exit Node (country-specific)")
    print(f"  4. Exit Node → Target Service")
    
    # Example of how to run real analysis when log files exist
    print(f"\n💡 To run real analysis:")
    print(f"   analyzer = NetStealthAnalyzer()")
    print(f"   result = analyzer.analyze_single_file('your_log_file.log')")
    print(f"   print(f'Score: {{result.summary.overall_score}}/100')")
    
    print(f"\n📈 For multiple files:")
    print(f"   result = analyzer.analyze(['log1.log', 'log2.har', 'log3.txt'])")
    print(f"   analyzer.export_results(result, 'report.json')")

if __name__ == "__main__":
    # Setup basic logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    main()
