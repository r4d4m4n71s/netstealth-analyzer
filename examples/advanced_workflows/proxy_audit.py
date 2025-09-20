#!/usr/bin/env python3
"""
NetStealth Analyzer Example: Comprehensive Proxy Security Audit

Description: Advanced example demonstrating comprehensive proxy security analysis.
This example shows how to perform a detailed audit of proxy configurations,
detect potential leaks, and generate actionable security recommendations.

Requirements:
- NetStealth Analyzer v2.0+
- HAR files from proxy sessions
- Mitmproxy logs (optional)

Usage:
    python proxy_audit.py
"""

import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from netstealth_analyzer import NetStealthAnalyzer
from netstealth_analyzer.core.events import AnalysisEvent


class ProxySecurityAuditor:
    """
    Comprehensive proxy security auditor.
    
    This class demonstrates advanced usage patterns including:
    - Multi-file analysis
    - Event-driven progress tracking
    - Custom issue categorization
    - Detailed reporting
    - Security recommendations
    """
    
    def __init__(self):
        self.audit_results = {}
        self.security_recommendations = []
        self.progress_data = {}
    
    async def run_comprehensive_audit(self, log_files: List[str], target_service: str) -> Dict[str, Any]:
        """
        Run comprehensive proxy security audit.
        
        Args:
            log_files: List of log files to analyze
            target_service: Target service domain
            
        Returns:
            Comprehensive audit results
        """
        
        print("🛡️  NetStealth Analyzer - Comprehensive Proxy Security Audit")
        print("=" * 60)
        
        # Validate input files
        validated_files = self._validate_log_files(log_files)
        if not validated_files:
            print("❌ No valid log files found for analysis")
            return {}
        
        print(f"📁 Analyzing {len(validated_files)} log files for {target_service}")
        
        try:
            # Create analyzer with comprehensive configuration
            analyzer = await self._create_analyzer(validated_files, target_service)
            
            # Run analysis with progress tracking
            result = await self._run_analysis_with_tracking(analyzer)
            
            if not result:
                return {}
            
            # Process and categorize results
            audit_results = await self._process_audit_results(result)
            
            # Generate security recommendations
            recommendations = self._generate_security_recommendations(audit_results)
            
            # Create comprehensive report
            final_report = self._create_comprehensive_report(
                audit_results, recommendations, target_service
            )
            
            # Save detailed reports
            await self._save_audit_reports(analyzer, result, final_report)
            
            # Cleanup
            await analyzer.shutdown()
            
            return final_report
            
        except Exception as e:
            print(f"❌ Audit failed: {e}")
            import traceback
            traceback.print_exc()
            return {}
    
    def _validate_log_files(self, log_files: List[str]) -> List[str]:
        """Validate that log files exist and are readable."""
        
        validated = []
        
        for file_path in log_files:
            path = Path(file_path)
            
            if not path.exists():
                print(f"⚠️  File not found: {file_path}")
                continue
            
            if not path.is_file():
                print(f"⚠️  Not a file: {file_path}")
                continue
            
            # Check file size
            size_mb = path.stat().st_size / (1024 * 1024)
            if size_mb > 500:  # 500MB limit
                print(f"⚠️  File too large ({size_mb:.1f}MB): {file_path}")
                print("   Consider using streaming analysis for large files")
                continue
            
            validated.append(str(path))
            print(f"✅ Validated: {file_path} ({size_mb:.1f}MB)")
        
        return validated
    
    async def _create_analyzer(self, log_files: List[str], target_service: str) -> NetStealthAnalyzer:
        """Create analyzer with comprehensive proxy detection configuration."""
        
        print("\n🔧 Configuring analyzer for proxy security audit...")
        
        # Define event handlers
        async def on_analysis_started(event, data):
            print(f"🚀 Analysis started - {data.get('components_count', 0)} components loaded")
            self.progress_data['start_time'] = datetime.now()
        
        async def on_progress_update(event, data):
            percentage = data.get('percentage', 0)
            message = data.get('message', 'Processing...')
            print(f"📊 Progress: {percentage:.1f}% - {message}")
        
        async def on_issue_found(event, data):
            severity_icons = {
                'critical': '💥', 'high': '🚨', 
                'medium': '⚠️', 'low': 'ℹ️'
            }
            icon = severity_icons.get(data.severity, '❓')
            print(f"   {icon} Found: {data.title} ({data.severity})")
        
        async def on_detector_completed(event, data):
            detector_name = data.get('detector_name', 'Unknown')
            issues_found = data.get('issues_found', 0)
            duration = data.get('duration_ms', 0)
            print(f"✅ {detector_name} detector completed: {issues_found} issues ({duration}ms)")
        
        async def on_analysis_completed(event, data):
            duration = data.get('duration_ms', 0)
            issues_count = data.get('issues_count', 0)
            print(f"🎉 Analysis completed: {issues_count} issues found ({duration}ms)")
            self.progress_data['end_time'] = datetime.now()
        
        # Create analyzer with focus on proxy and network detection and register event handlers
        analyzer = (NetStealthAnalyzer.create()
                    .with_logs(*log_files)  # Unpack the list for the fluent API
                    .for_service(target_service)
                    .with_detectors("proxy", "network", "browser")  # Focus on proxy-related detectors
                    .enable_fingerprint_analysis()  # Enable detailed fingerprinting
                    .timeout(600)  # 10 minute timeout for thorough analysis
                    .on(AnalysisEvent.ANALYSIS_STARTED, on_analysis_started)
                    .on(AnalysisEvent.PROGRESS_UPDATE, on_progress_update)
                    .on(AnalysisEvent.ISSUE_FOUND, on_issue_found)
                    .on(AnalysisEvent.DETECTOR_COMPLETED, on_detector_completed)
                    .on(AnalysisEvent.ANALYSIS_COMPLETED, on_analysis_completed)
                    .build())
        
        print("✅ Analyzer configured for comprehensive proxy audit")
        return analyzer
    
    
    async def _run_analysis_with_tracking(self, analyzer: NetStealthAnalyzer):
        """Run analysis with comprehensive error handling and tracking."""
        
        print("\n🔍 Starting comprehensive proxy security analysis...")
        
        try:
            result = await analyzer.analyze()
            print("✅ Analysis completed successfully")
            return result
            
        except asyncio.TimeoutError:
            print("❌ Analysis timed out")
            print("💡 Try reducing the scope or increasing timeout")
            return None
            
        except Exception as e:
            print(f"❌ Analysis failed: {e}")
            return None
    
    async def _process_audit_results(self, result) -> Dict[str, Any]:
        """Process and categorize audit results for proxy security focus."""
        
        print("\n📋 Processing audit results...")
        
        # Categorize issues by type
        proxy_issues = []
        network_issues = []
        browser_issues = []
        other_issues = []
        
        for issue in result.issues:
            category = issue.category.value.lower()
            
            if 'proxy' in category or 'ip' in category:
                proxy_issues.append(issue)
            elif 'network' in category or 'routing' in category:
                network_issues.append(issue)
            elif 'browser' in category or 'automation' in category:
                browser_issues.append(issue)
            else:
                other_issues.append(issue)
        
        # Calculate risk scores
        risk_scores = self._calculate_risk_scores(result.issues)
        
        # Analyze network traces for proxy patterns
        proxy_patterns = self._analyze_proxy_patterns(result.network_traces)
        
        audit_results = {
            'overall_score': result.summary.overall_score,
            'total_issues': len(result.issues),
            'issue_categories': {
                'proxy_issues': len(proxy_issues),
                'network_issues': len(network_issues),
                'browser_issues': len(browser_issues),
                'other_issues': len(other_issues)
            },
            'risk_assessment': risk_scores,
            'proxy_patterns': proxy_patterns,
            'detailed_issues': {
                'proxy': [self._issue_to_dict(issue) for issue in proxy_issues],
                'network': [self._issue_to_dict(issue) for issue in network_issues],
                'browser': [self._issue_to_dict(issue) for issue in browser_issues],
                'other': [self._issue_to_dict(issue) for issue in other_issues]
            },
            'network_analysis': {
                'total_traces': len(result.network_traces),
                'unique_ips': len(set(trace.client_ip for trace in result.network_traces 
                                    if hasattr(trace, 'client_ip'))),
                'trace_summary': [self._trace_to_dict(trace) for trace in result.network_traces[:5]]
            }
        }
        
        print(f"✅ Processed {len(result.issues)} issues across {len(result.network_traces)} network traces")
        return audit_results
    
    def _calculate_risk_scores(self, issues: List) -> Dict[str, Any]:
        """Calculate comprehensive risk scores."""
        
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 1
        }
        
        total_risk = 0
        severity_counts = {}
        
        for issue in issues:
            severity = issue.severity.value
            weight = severity_weights.get(severity, 1)
            confidence = getattr(issue, 'confidence', 0.5)
            
            # Risk = severity weight * confidence
            risk_contribution = weight * confidence
            total_risk += risk_contribution
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Normalize risk score (0-100)
        max_possible_risk = len(issues) * 10  # All critical issues
        normalized_risk = min(100, (total_risk / max_possible_risk * 100)) if max_possible_risk > 0 else 0
        
        return {
            'total_risk_score': round(total_risk, 2),
            'normalized_risk': round(normalized_risk, 1),
            'risk_level': self._get_risk_level(normalized_risk),
            'severity_breakdown': severity_counts
        }
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level."""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _analyze_proxy_patterns(self, network_traces: List) -> Dict[str, Any]:
        """Analyze network traces for proxy usage patterns."""
        
        patterns = {
            'proxy_chains_detected': 0,
            'direct_connections': 0,
            'suspicious_routing': 0,
            'geographic_inconsistencies': 0,
            'common_proxy_ips': {},
            'routing_patterns': []
        }
        
        for trace in network_traces:
            # Analyze hops for proxy patterns
            if len(trace.hops) > 2:  # More than direct connection
                patterns['proxy_chains_detected'] += 1
            elif len(trace.hops) <= 2:
                patterns['direct_connections'] += 1
            
            # Look for suspicious routing (simplified)
            if len(trace.hops) > 5:
                patterns['suspicious_routing'] += 1
            
            # Track common IPs (simplified)
            for hop in trace.hops:
                if hasattr(hop, 'outgoing_ip') and hop.outgoing_ip:
                    ip = hop.outgoing_ip
                    patterns['common_proxy_ips'][ip] = patterns['common_proxy_ips'].get(ip, 0) + 1
        
        return patterns
    
    def _generate_security_recommendations(self, audit_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable security recommendations based on audit results."""
        
        print("\n💡 Generating security recommendations...")
        
        recommendations = []
        risk_level = audit_results['risk_assessment']['risk_level']
        issue_categories = audit_results['issue_categories']
        
        # High-level recommendations based on risk
        if risk_level in ['CRITICAL', 'HIGH']:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Immediate Action Required',
                'title': 'Critical Security Issues Detected',
                'description': f'Your proxy configuration has {risk_level.lower()} risk issues that require immediate attention.',
                'actions': [
                    'Review all critical and high severity issues',
                    'Implement recommended fixes immediately',
                    'Re-run analysis after fixes to verify improvements',
                    'Consider additional security measures'
                ]
            })
        
        # Proxy-specific recommendations
        if issue_categories['proxy_issues'] > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Proxy Configuration',
                'title': 'Proxy Security Issues Detected',
                'description': f'Found {issue_categories["proxy_issues"]} proxy-related security issues.',
                'actions': [
                    'Review proxy headers for information leakage',
                    'Check for IP address exposure',
                    'Verify proxy chain configuration',
                    'Test for DNS leaks',
                    'Validate geographic consistency'
                ]
            })
        
        # Network recommendations
        if issue_categories['network_issues'] > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Network Security',
                'title': 'Network Routing Issues',
                'description': f'Detected {issue_categories["network_issues"]} network-related issues.',
                'actions': [
                    'Review network routing patterns',
                    'Check for unusual network hops',
                    'Verify geographic routing consistency',
                    'Monitor for routing anomalies'
                ]
            })
        
        # Browser recommendations
        if issue_categories['browser_issues'] > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Browser Security',
                'title': 'Browser Detection Issues',
                'description': f'Found {issue_categories["browser_issues"]} browser-related detection issues.',
                'actions': [
                    'Review browser automation signatures',
                    'Check for fingerprinting vulnerabilities',
                    'Verify user agent consistency',
                    'Test browser stealth configurations'
                ]
            })
        
        # General recommendations
        recommendations.append({
            'priority': 'LOW',
            'category': 'Best Practices',
            'title': 'Security Best Practices',
            'description': 'General recommendations for maintaining proxy security.',
            'actions': [
                'Regularly audit proxy configurations',
                'Monitor for new detection methods',
                'Keep proxy software updated',
                'Implement comprehensive logging',
                'Regular security assessments'
            ]
        })
        
        print(f"✅ Generated {len(recommendations)} security recommendations")
        return recommendations
    
    def _create_comprehensive_report(self, audit_results: Dict[str, Any], 
                                   recommendations: List[Dict[str, Any]], 
                                   target_service: str) -> Dict[str, Any]:
        """Create comprehensive audit report."""
        
        return {
            'audit_metadata': {
                'timestamp': datetime.now().isoformat(),
                'target_service': target_service,
                'analyzer_version': '2.0.0',
                'audit_type': 'Comprehensive Proxy Security Audit'
            },
            'executive_summary': {
                'overall_score': audit_results['overall_score'],
                'risk_level': audit_results['risk_assessment']['risk_level'],
                'total_issues': audit_results['total_issues'],
                'critical_issues': audit_results['risk_assessment']['severity_breakdown'].get('critical', 0),
                'high_issues': audit_results['risk_assessment']['severity_breakdown'].get('high', 0),
                'recommendations_count': len(recommendations)
            },
            'detailed_results': audit_results,
            'security_recommendations': recommendations,
            'next_steps': [
                'Review all critical and high severity issues',
                'Implement recommended security fixes',
                'Re-run audit to verify improvements',
                'Schedule regular security audits',
                'Monitor for new threats and detection methods'
            ]
        }
    
    async def _save_audit_reports(self, analyzer: NetStealthAnalyzer, result, final_report: Dict[str, Any]):
        """Save comprehensive audit reports in multiple formats."""
        
        print("\n📄 Generating comprehensive audit reports...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            # Save detailed JSON report
            json_file = f"proxy_audit_detailed_{timestamp}.json"
            with open(json_file, 'w') as f:
                json.dump(final_report, f, indent=2, default=str)
            print(f"✅ Detailed JSON report: {json_file}")
            
            # Save HTML report using Report class
            html_file = f"proxy_audit_report_{timestamp}.html"
            from netstealth_analyzer.reporting.reporter import Report
            report_obj = Report(analysis_result=result)
            report_obj.save_html(html_file)
            print(f"✅ HTML report: {html_file}")
            
            # Save executive summary
            summary_file = f"proxy_audit_summary_{timestamp}.json"
            with open(summary_file, 'w') as f:
                json.dump(final_report['executive_summary'], f, indent=2)
            print(f"✅ Executive summary: {summary_file}")
            
        except Exception as e:
            print(f"⚠️  Error saving reports: {e}")
    
    def _issue_to_dict(self, issue) -> Dict[str, Any]:
        """Convert issue object to dictionary."""
        return {
            'title': issue.title,
            'severity': issue.severity.value,
            'category': issue.category.value,
            'confidence': getattr(issue, 'confidence', 0.0),
            'description': issue.description,
            'evidence_count': len(getattr(issue, 'evidence', [])),
            'remediation_count': len(getattr(issue, 'remediation_suggestions', []))
        }
    
    def _trace_to_dict(self, trace) -> Dict[str, Any]:
        """Convert network trace to dictionary summary."""
        return {
            'trace_id': trace.trace_id,
            'hops_count': len(trace.hops),
            'timestamp': trace.timestamp.isoformat() if trace.timestamp else None,
            'has_metadata': bool(trace.metadata)
        }


async def main():
    """Main function demonstrating comprehensive proxy security audit."""
    
    # Example log files (in real usage, these would be your actual files)
    log_files = [
        "../sample_data/sample_session.har",
        "../sample_data/sample_proxy.log"
    ]
    
    target_service = "target-service.com"
    
    # Create auditor and run comprehensive audit
    auditor = ProxySecurityAuditor()
    
    print("Starting comprehensive proxy security audit...\n")
    
    try:
        audit_report = await auditor.run_comprehensive_audit(log_files, target_service)
        
        if audit_report:
            # Display executive summary
            summary = audit_report['executive_summary']
            print(f"\n🎯 Executive Summary:")
            print(f"   Overall Score: {summary['overall_score']}/100")
            print(f"   Risk Level: {summary['risk_level']}")
            print(f"   Total Issues: {summary['total_issues']}")
            print(f"   Critical Issues: {summary['critical_issues']}")
            print(f"   High Issues: {summary['high_issues']}")
            print(f"   Recommendations: {summary['recommendations_count']}")
            
            # Show top recommendations
            recommendations = audit_report['security_recommendations']
            print(f"\n🔧 Top Security Recommendations:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"   {i}. {rec['title']} ({rec['priority']})")
                print(f"      {rec['description']}")
            
            print(f"\n✅ Comprehensive proxy security audit completed!")
            print(f"📊 Check generated reports for detailed analysis")
            
        else:
            print(f"\n❌ Audit failed to complete")
            
    except KeyboardInterrupt:
        print(f"\n⏹️  Audit interrupted by user")
        
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
