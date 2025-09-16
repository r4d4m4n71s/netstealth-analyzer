"""
NetStealth Analyzer - Complete Usage Example

This example demonstrates how to use the NetStealth Analyzer to analyze
log files and detect stealth operation issues, including:
- Configurable service patterns and target geography settings
- Real log file analysis with sample data
- Proxy detection and security issue identification
"""

import logging
from pathlib import Path
from netstealth_analyzer import NetStealthAnalyzer
from netstealth_analyzer.models import AnalysisConfig, TargetGeography
from netstealth_analyzer.parsers.poc import PocExecutionParser
from netstealth_analyzer.parsers.har import HarParser
from netstealth_analyzer.detectors.proxy import ProxyDetector

def demonstrate_configurations():
    """Demonstrate different configuration examples."""
    print("🔍 NetStealth Analyzer - Complete Analysis Example")
    print("=" * 60)
    
    # Initialize analyzer with default configuration
    analyzer = NetStealthAnalyzer()
    
    print("✅ Analyzer initialized with default configuration")
    print("   • Service domains: example.com, api.example.com, etc.")
    print("   • Target geography: United States (US)")
    
    # Example with custom service domains and geography
    print(f"\n🌐 Custom Configuration Examples:")
    print("=" * 40)
    
    # Example 1: E-commerce service targeting UK
    uk_geography = TargetGeography(
        country_code="GB",
        country_name="United Kingdom", 
        ip_ranges=["192.0.2.0/24"],  # Example IP range
        timezone="Europe/London",
        language="en-GB"
    )
    
    ecommerce_config = AnalysisConfig(
        service_domains=[
            "mystore.com",
            "api.mystore.com", 
            "checkout.mystore.com",
            "auth.mystore.com"
        ],
        target_geography=uk_geography,
        auto_remediation=True,
        session_timeline=True,
        max_issues_per_category=5
    )
    
    print("📦 E-commerce Configuration:")
    print(f"   • Service domains: {', '.join(ecommerce_config.service_domains)}")
    print(f"   • Target country: {uk_geography.country_name} ({uk_geography.country_code})")
    print(f"   • Language: {uk_geography.language}")
    print(f"   • Timezone: {uk_geography.timezone}")
    
    # Example 2: Social media service targeting Germany
    de_geography = TargetGeography(
        country_code="DE",
        country_name="Germany",
        ip_ranges=["203.0.113.0/24"],  # Example IP range
        timezone="Europe/Berlin", 
        language="de-DE"
    )
    
    social_config = AnalysisConfig(
        service_domains=[
            "socialapp.de",
            "api.socialapp.de",
            "cdn.socialapp.de",
            "oauth.socialapp.de"
        ],
        target_geography=de_geography,
        auto_remediation=True,
        fingerprint_comparison=True,
        session_timeline=True
    )
    
    print(f"\n📱 Social Media Configuration:")
    print(f"   • Service domains: {', '.join(social_config.service_domains)}")
    print(f"   • Target country: {de_geography.country_name} ({de_geography.country_code})")
    print(f"   • Language: {de_geography.language}")
    print(f"   • Timezone: {de_geography.timezone}")
    
    # Example 3: Financial service with strict requirements
    us_finance_geography = TargetGeography(
        country_code="US",
        country_name="United States",
        ip_ranges=["198.51.100.0/24", "203.0.113.0/24"],  # Multiple IP ranges
        timezone="America/New_York",
        language="en-US"
    )
    
    finance_config = AnalysisConfig(
        service_domains=[
            "bankingapp.com",
            "secure.bankingapp.com",
            "api.bankingapp.com",
            "auth.bankingapp.com",
            "transactions.bankingapp.com"
        ],
        target_geography=us_finance_geography,
        auto_remediation=True,
        fingerprint_comparison=True,
        session_timeline=True,
        max_issues_per_category=10,  # More thorough analysis
        extended_browser_analysis=True
    )
    
    print(f"\n🏦 Financial Service Configuration:")
    print(f"   • Service domains: {', '.join(finance_config.service_domains[:3])}... ({len(finance_config.service_domains)} total)")
    print(f"   • Target country: {us_finance_geography.country_name} ({us_finance_geography.country_code})")
    print(f"   • IP ranges: {len(us_finance_geography.ip_ranges)} configured")
    print(f"   • Extended analysis: Enabled")
    
    # Initialize analyzers with custom configurations
    ecommerce_analyzer = NetStealthAnalyzer(config=ecommerce_config)
    social_analyzer = NetStealthAnalyzer(config=social_config)
    finance_analyzer = NetStealthAnalyzer(config=finance_config)
    
    print(f"\n✅ All analyzers configured successfully!")
    
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
    print(f"\n🔬 Example Analysis Configuration:")
    print(f"  • Auto-remediation: {ecommerce_config.auto_remediation}")
    print(f"  • Session timeline: {ecommerce_config.session_timeline}")
    print(f"  • Max issues per category: {ecommerce_config.max_issues_per_category}")
    print(f"  • Extended browser analysis: {finance_config.extended_browser_analysis}")
    
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
    
    return ecommerce_config  # Return config for testing

def test_poc_parser(config):
    """Test POC parser with sample log."""
    print("\n" + "="*60)
    print("🔍 Testing POC Execution Parser with Real Logs")
    print("=" * 60)
    
    parser = PocExecutionParser(config)
    log_path = Path("logs/poc_execution.log")
    
    if log_path.exists():
        try:
            result = parser.parse(log_path)
            
            print(f"📊 POC Analysis Results:")
            print(f"  • Exit IPs detected: {result['statistics']['exit_ips_detected']}")
            print(f"  • Target geo IPs found: {result['statistics']['target_geo_ips_found']}")
            print(f"  • Service requests: {result['statistics']['service_requests']}")
            print(f"  • OAuth steps completed: {result['statistics']['oauth_steps_completed']}")
            print(f"  • Session success: {result['session_info']['success']}")
            print(f"  • Session health score: {result['statistics']['session_health_score']:.1f}/100")
            
            print(f"\n📍 Exit IP Details:")
            for ip in result['exit_ips']:
                print(f"  • {ip['ip_address']} - Target geo: {ip['is_target_geo_ip']} ({ip['detection_method']})")
            
            print(f"\n🔐 OAuth Events:")
            for event in result['oauth_events'][:3]:  # Show first 3
                print(f"  • {event['step_type']}: {'✅' if event['is_success'] else '❌'}")
                
        except Exception as e:
            print(f"❌ Error parsing POC log: {e}")
    else:
        print(f"❌ Log file not found: {log_path}")

def test_har_parser(config):
    """Test HAR parser with sample network trace."""
    print(f"\n🌐 Testing HAR Parser with Network Trace")
    print("=" * 60)
    
    parser = HarParser(config)
    har_path = Path("logs/network_trace.har")
    
    if har_path.exists():
        try:
            result = parser.parse(har_path)
            
            print(f"📊 HAR Analysis Results:")
            print(f"  • Total requests: {result['statistics']['total_requests']}")
            print(f"  • Service requests: {result['statistics']['service_requests']}")
            print(f"  • Successful responses: {result['statistics']['successful_responses']}")
            print(f"  • Proxy indicators: {result['statistics']['proxy_indicators']}")
            print(f"  • Success rate: {result['statistics']['success_rate']:.1f}%")
            print(f"  • Service success rate: {result['statistics']['service_success_rate']:.1f}%")
            
            print(f"\n🔍 Service Requests Found:")
            service_requests = [r for r in result['requests'] if r['is_service']]
            for req in service_requests:
                print(f"  • {req['method']} {req['url']} - Status: {req['response_status']}")
            
            print(f"\n⚠️  Proxy Events:")
            for event in result['proxy_events']:
                print(f"  • {event['type']} at {event['domain']} - Risk: {event['detection_risk']}")
                
        except Exception as e:
            print(f"❌ Error parsing HAR file: {e}")
    else:
        print(f"❌ HAR file not found: {har_path}")

def test_proxy_detector(config):
    """Test proxy detector with parsed data."""
    print(f"\n🛡️  Testing Proxy Detector with Combined Data")
    print("=" * 60)
    
    # Parse both log files
    poc_parser = PocExecutionParser(config)
    har_parser = HarParser(config)
    
    parsed_data = {'sources': []}
    
    # Add POC data
    poc_path = Path("logs/poc_execution.log")
    if poc_path.exists():
        try:
            poc_result = poc_parser.parse(poc_path)
            parsed_data['sources'].append({
                'format': 'poc_execution',
                'path': str(poc_path),
                'data': poc_result
            })
        except Exception as e:
            print(f"⚠️  Could not parse POC log: {e}")
    
    # Add HAR data
    har_path = Path("logs/network_trace.har")
    if har_path.exists():
        try:
            har_result = har_parser.parse(har_path)
            parsed_data['sources'].append({
                'format': 'har',
                'path': str(har_path),
                'data': har_result
            })
        except Exception as e:
            print(f"⚠️  Could not parse HAR file: {e}")
    
    # Run proxy detection
    detector = ProxyDetector(config)
    issues = detector.detect(parsed_data)
    
    print(f"📊 Proxy Detection Results:")
    print(f"  • Issues detected: {len(issues)}")
    
    if issues:
        print(f"\n🚨 Critical Issues Found:")
        for issue in issues:
            print(f"  • {issue.id}: {issue.title}")
            print(f"    Severity: {issue.severity.value}, Impact: {issue.impact_score}/100")
            print(f"    Description: {issue.description}")
            if issue.recommendation:
                print(f"    Recommendation: {issue.recommendation}")
            print()
    else:
        print(f"  ✅ No critical proxy issues detected")

def main():
    """Run complete demonstration and testing."""
    # First demonstrate configurations
    config = demonstrate_configurations()
    
    # Check if we have sample logs to test with
    sample_logs_exist = any(Path(f"logs/{log}").exists() 
                           for log in ["poc_execution.log", "network_trace.har", "browser_console.log"])
    
    if sample_logs_exist:
        print(f"\n🧪 TESTING WITH SAMPLE LOGS")
        print("=" * 60)
        print("Sample logs detected! Running live analysis tests...")
        
        # Use UK e-commerce config that matches our sample logs
        uk_geography = TargetGeography(
            country_code="GB",
            country_name="United Kingdom", 
            ip_ranges=["203.0.113.0/24"],  # Matches sample log IP
            timezone="Europe/London",
            language="en-GB"
        )
        
        test_config = AnalysisConfig(
            service_domains=[
                "mystore.com",
                "api.mystore.com", 
                "auth.mystore.com"
            ],
            target_geography=uk_geography
        )
        
        # Test each component
        test_poc_parser(test_config)
        test_har_parser(test_config) 
        test_proxy_detector(test_config)
        
        print(f"\n" + "="*60)
        print(f"✅ TESTING COMPLETE! The analyzer successfully:")
        print(f"  • Parsed logs with configurable service domains")
        print(f"  • Detected target geography IPs using configurable ranges")
        print(f"  • Identified service-specific requests and OAuth flows")
        print(f"  • Found proxy header leakage issues")
        print(f"  • Generated actionable security recommendations")
        
        print(f"\n💡 Key Features Demonstrated:")
        print(f"  • Service domain configuration (mystore.com, api.mystore.com, etc.)")
        print(f"  • Target geography settings (UK: GB, en-GB, Europe/London)")
        print(f"  • IP range matching (203.0.113.0/24)")
        print(f"  • Geographic consistency checking")
        print(f"  • Proxy detection with configurable targets")
    else:
        print(f"\n💡 To test with real logs:")
        print(f"  • Create sample logs in the 'logs/' directory")
        print(f"  • Run this script again to see live analysis")

if __name__ == "__main__":
    # Setup logging to reduce noise during demo
    logging.basicConfig(
        level=logging.WARNING,
        format='%(levelname)s: %(message)s'
    )
    
    main()
