"""Summary report generator for TIDAL Stealth Analyzer."""

from typing import Dict, List
from tabulate import tabulate
from ..models import AnalysisResult, AnalysisConfig


class SummaryReportGenerator:
    """Generates summary reports from analysis results."""
    
    def __init__(self, config: AnalysisConfig):
        self.config = config
    
    def generate_text_report(self, result: AnalysisResult) -> str:
        """Generate a human-readable text report."""
        lines = []
        
        # Header
        lines.append("=" * 70)
        lines.append("🔍 TIDAL STEALTH ANALYZER REPORT")
        lines.append("=" * 70)
        lines.append(f"Analysis Date: {result.summary.timestamp}")
        lines.append(f"Overall Status: {result.summary.status}")
        lines.append(f"Success Score: {result.summary.overall_score}%")
        lines.append("")
        
        # Critical Issues
        lines.append("⚠️ CRITICAL ISSUES")
        lines.append("-" * 30)
        if result.critical_issues:
            for i, issue in enumerate(result.critical_issues[:5], 1):
                lines.append(f"{i}. {issue.title}")
                lines.append(f"   Severity: {issue.severity.value}")
                lines.append(f"   Impact: {issue.impact_score}/100")
                lines.append(f"   Fix: {issue.recommendation or 'No recommendation'}")
                lines.append("")
        else:
            lines.append("✅ No critical issues detected")
            lines.append("")
        
        # Network Trace Table
        lines.append("🌐 NETWORK TRACE")
        lines.append("-" * 30)
        if result.network_trace:
            table_data = result.get_network_trace_table()
            lines.append(tabulate(table_data, headers='firstrow', tablefmt='grid'))
        else:
            lines.append("No network trace data available")
        lines.append("")
        
        # Performance Summary
        lines.append("📊 PERFORMANCE METRICS")
        lines.append("-" * 30)
        perf = result.performance_metrics
        lines.append(f"Total Requests: {perf.total_requests}")
        lines.append(f"Success Rate: {perf.success_rate_percent:.1f}%")
        lines.append(f"Average Response Time: {perf.average_response_time_ms:.1f}ms")
        lines.append("")
        
        # Recommendations
        if result.remediation_suggestions:
            lines.append("💡 RECOMMENDATIONS")
            lines.append("-" * 30)
            for i, suggestion in enumerate(result.remediation_suggestions[:3], 1):
                lines.append(f"{i}. {suggestion.get('title', 'Unknown')}")
                lines.append(f"   {suggestion.get('recommendation', 'No details')}")
                if suggestion.get('code_fix'):
                    lines.append(f"   Code: {suggestion['code_fix']}")
                lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def generate_json_summary(self, result: AnalysisResult) -> Dict:
        """Generate a JSON summary of key findings."""
        return {
            "status": result.summary.status,
            "score": result.summary.overall_score,
            "critical_issues": len(result.critical_issues),
            "total_issues": result.summary.total_issues_count,
            "network_hops": len(result.network_trace),
            "success_rate": result.performance_metrics.success_rate_percent,
            "key_issues": [
                {
                    "id": issue.id,
                    "title": issue.title,
                    "severity": issue.severity.value,
                    "impact": issue.impact_score
                }
                for issue in result.critical_issues[:5]
            ]
        }
