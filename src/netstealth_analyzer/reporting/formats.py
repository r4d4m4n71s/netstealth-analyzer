"""
Report formatters for NetStealth Analyzer.

This module provides various output formatters for analysis reports including
JSON, Markdown, HTML, and YAML formats with comprehensive styling and structure.
"""

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List
from datetime import datetime

from ..models.issues import Issue
from ..models.enums import SeverityLevel, IssueCategory


class ReportFormatter(ABC):
    """Abstract base class for report formatters."""
    
    @abstractmethod
    def format(self, report: 'Report') -> str:
        """Format the report into the target format."""
        pass


class JsonFormatter(ReportFormatter):
    """JSON report formatter with structured output."""
    
    def __init__(self, indent: int = 2, include_metadata: bool = True):
        """Initialize JSON formatter."""
        self.indent = indent
        self.include_metadata = include_metadata
    
    def format(self, report: 'Report') -> str:
        """Format report as JSON."""
        data = {
            'netstealth_analyzer': {
                'version': '2.0.0',
                'report_generated': datetime.now().isoformat(),
                'format': 'json'
            },
            'summary': report.get_summary(),
            'issues': [self._format_issue(issue) for issue in report.issues]
        }
        
        if self.include_metadata:
            data['configuration'] = report.config
            data['statistics'] = report.statistics
        
        return json.dumps(data, indent=self.indent, default=str, ensure_ascii=False)
    
    def _format_issue(self, issue: Issue) -> Dict[str, Any]:
        """Format a single issue for JSON output."""
        # Handle enum values safely
        category_value = issue.category.value if hasattr(issue.category, 'value') else str(issue.category)
        severity_value = issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity)
        
        return {
            'id': issue.id,
            'title': issue.title,
            'description': issue.description,
            'category': category_value,
            'severity': severity_value,
            'confidence': issue.confidence,
            'timestamp': issue.detection_timestamp.isoformat() if issue.detection_timestamp else None,
            'evidence': [
                {
                    'type': evidence.type,
                    'description': evidence.description,
                    'data': evidence.raw_data,
                    'metadata': evidence.metadata
                }
                for evidence in issue.evidence
            ],
            'remediation_suggestions': [r.title for r in issue.remediation_suggestions],
            'metadata': issue.metadata.model_dump() if hasattr(issue.metadata, 'model_dump') else issue.metadata
        }


class MarkdownFormatter(ReportFormatter):
    """Markdown report formatter with rich formatting."""
    
    def __init__(self, include_toc: bool = True, include_details: bool = True):
        """Initialize Markdown formatter."""
        self.include_toc = include_toc
        self.include_details = include_details
    
    def format(self, report: 'Report') -> str:
        """Format report as Markdown."""
        sections = []
        
        # Header
        sections.append(self._format_header(report))
        
        # Table of Contents
        if self.include_toc:
            sections.append(self._format_toc(report))
        
        # Executive Summary
        sections.append(self._format_summary(report))
        
        # Issues by Severity
        sections.append(self._format_issues_by_severity(report))
        
        # Detailed Issues
        if self.include_details:
            sections.append(self._format_detailed_issues(report))
        
        # Statistics
        sections.append(self._format_statistics(report))
        
        return '\n\n'.join(sections)
    
    def _format_header(self, report: 'Report') -> str:
        """Format report header."""
        risk_score = report.get_risk_score()
        risk_level = self._get_risk_level(risk_score)
        duration_str = f"{report.duration:.2f}s" if report.duration is not None else "N/A"
        
        return f"""# 🔍 NetStealth Analyzer Report

**Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Total Issues**: {report.issue_count}  
**Risk Score**: {risk_score}/100 ({risk_level})  
**Analysis Duration**: {duration_str}  

---"""
    
    def _format_toc(self, report: 'Report') -> str:
        """Format table of contents."""
        return """## 📋 Table of Contents

- [Executive Summary](#executive-summary)
- [Issues by Severity](#issues-by-severity)
- [Detailed Issues](#detailed-issues)
- [Statistics](#statistics)"""
    
    def _format_summary(self, report: 'Report') -> str:
        """Format executive summary."""
        summary = report.get_summary()
        severity_dist = summary['severity_distribution']
        
        return f"""## 📊 Executive Summary

### Severity Breakdown
- 🔴 **Critical**: {severity_dist['critical']} issues
- 🟠 **High**: {severity_dist['high']} issues  
- 🟡 **Medium**: {severity_dist['medium']} issues
- 🔵 **Low**: {severity_dist['low']} issues
- ℹ️ **Info**: {severity_dist['info']} issues

### Risk Assessment
**Overall Risk Score**: {summary['risk_score']}/100 ({self._get_risk_level(summary['risk_score'])})

{self._get_risk_description(summary['risk_score'])}"""
    
    def _format_issues_by_severity(self, report: 'Report') -> str:
        """Format issues grouped by severity."""
        sections = ["## 🚨 Issues by Severity"]
        
        severity_groups = [
            (SeverityLevel.CRITICAL, "🔴 Critical Issues", report.critical_issues),
            (SeverityLevel.HIGH, "🟠 High Severity Issues", report.high_issues),
            (SeverityLevel.MEDIUM, "🟡 Medium Severity Issues", report.medium_issues),
            (SeverityLevel.LOW, "🔵 Low Severity Issues", report.low_issues),
            (SeverityLevel.INFO, "ℹ️ Informational Issues", report.info_issues)
        ]
        
        for severity, title, issues in severity_groups:
            if issues:
                sections.append(f"### {title}")
                for issue in issues:
                    category_value = issue.category.value if hasattr(issue.category, 'value') else str(issue.category)
                    sections.append(f"- **{issue.title}** ({category_value})")
                    sections.append(f"  - Confidence: {issue.confidence:.1%}")
                    if issue.remediation_suggestions:
                        remediation = issue.remediation_suggestions[0].title if hasattr(issue.remediation_suggestions[0], 'title') else str(issue.remediation_suggestions[0])
                        sections.append(f"  - Remediation: {remediation}")
        
        return '\n\n'.join(sections)
    
    def _format_detailed_issues(self, report: 'Report') -> str:
        """Format detailed issue descriptions."""
        if not report.issues:
            return "## 📝 Detailed Issues\n\nNo issues found."
        
        sections = ["## 📝 Detailed Issues"]
        
        for i, issue in enumerate(report.issues, 1):
            sections.append(self._format_single_issue(issue, i))
        
        return '\n\n'.join(sections)
    
    def _format_single_issue(self, issue: Issue, index: int) -> str:
        """Format a single issue in detail."""
        severity_emoji = {
            SeverityLevel.CRITICAL: "🔴",
            SeverityLevel.HIGH: "🟠", 
            SeverityLevel.MEDIUM: "🟡",
            SeverityLevel.LOW: "🔵",
            SeverityLevel.INFO: "ℹ️"
        }.get(issue.severity, "❓")
        
        category_value = issue.category.value if hasattr(issue.category, 'value') else str(issue.category)
        severity_value = issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity)
        
        sections = [
            f"### {severity_emoji} Issue #{index}: {issue.title}",
            f"**Category**: {category_value}  ",
            f"**Severity**: {severity_value}  ",
            f"**Confidence**: {issue.confidence:.1%}  ",
            f"**Description**: {issue.description}"
        ]
        
        if issue.evidence:
            sections.append("**Evidence**:")
            for evidence in issue.evidence:
                sections.append(f"- {evidence.description}: `{evidence.raw_data}`")
        
        if issue.remediation_suggestions:
            sections.append("**Remediation Suggestions**:")
            for suggestion in issue.remediation_suggestions:
                sections.append(f"- {suggestion}")
        
        return '\n'.join(sections)
    
    def _format_statistics(self, report: 'Report') -> str:
        """Format analysis statistics."""
        stats = report.statistics
        duration_str = f"{report.duration:.2f} seconds" if report.duration is not None else "N/A"
        
        sections = [
            "## 📈 Analysis Statistics",
            f"**Analysis Start**: {report.start_time.strftime('%Y-%m-%d %H:%M:%S UTC') if report.start_time else 'N/A'}  ",
            f"**Analysis End**: {report.end_time.strftime('%Y-%m-%d %H:%M:%S UTC') if report.end_time else 'N/A'}  ",
            f"**Duration**: {duration_str}  "
        ]
        
        if stats:
            sections.append("**Processing Statistics**:")
            for key, value in stats.items():
                if isinstance(value, (int, float)):
                    sections.append(f"- {key.replace('_', ' ').title()}: {value}")
        
        return '\n'.join(sections)
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level description from score."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _get_risk_description(self, score: float) -> str:
        """Get detailed risk description."""
        if score >= 80:
            return "⚠️ **IMMEDIATE ACTION REQUIRED**: Critical security issues detected that require immediate attention."
        elif score >= 60:
            return "🔶 **HIGH PRIORITY**: Significant security concerns that should be addressed promptly."
        elif score >= 40:
            return "🔸 **MODERATE RISK**: Some security issues present that should be reviewed and addressed."
        elif score >= 20:
            return "🔹 **LOW RISK**: Minor security considerations that can be addressed as time permits."
        else:
            return "✅ **MINIMAL RISK**: No significant security issues detected."


class HtmlFormatter(ReportFormatter):
    """HTML report formatter with modern styling."""
    
    def __init__(self, include_css: bool = True, dark_theme: bool = False):
        """Initialize HTML formatter."""
        self.include_css = include_css
        self.dark_theme = dark_theme
    
    def format(self, report: 'Report') -> str:
        """Format report as HTML."""
        html_parts = [
            self._get_html_header(),
            self._get_css_styles() if self.include_css else "",
            self._format_body(report),
            self._get_html_footer()
        ]
        
        return '\n'.join(filter(None, html_parts))
    
    def _get_html_header(self) -> str:
        """Get HTML document header."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetStealth Analyzer Report</title>
</head>"""
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for the report."""
        theme_colors = {
            'bg': '#1a1a1a' if self.dark_theme else '#ffffff',
            'text': '#ffffff' if self.dark_theme else '#333333',
            'border': '#444444' if self.dark_theme else '#dddddd',
            'card_bg': '#2d2d2d' if self.dark_theme else '#f8f9fa'
        }
        
        return f"""<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        line-height: 1.6;
        margin: 0;
        padding: 20px;
        background-color: {theme_colors['bg']};
        color: {theme_colors['text']};
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{ text-align: center; margin-bottom: 30px; }}
    .summary-card {{
        background: {theme_colors['card_bg']};
        border: 1px solid {theme_colors['border']};
        border-radius: 8px;
        padding: 20px;
        margin: 20px 0;
    }}
    .severity-critical {{ color: #dc3545; }}
    .severity-high {{ color: #fd7e14; }}
    .severity-medium {{ color: #ffc107; }}
    .severity-low {{ color: #0dcaf0; }}
    .severity-info {{ color: #6c757d; }}
    .issue-card {{
        border-left: 4px solid #007bff;
        background: {theme_colors['card_bg']};
        padding: 15px;
        margin: 10px 0;
        border-radius: 4px;
    }}
    .issue-card.critical {{ border-left-color: #dc3545; }}
    .issue-card.high {{ border-left-color: #fd7e14; }}
    .issue-card.medium {{ border-left-color: #ffc107; }}
    .issue-card.low {{ border-left-color: #0dcaf0; }}
    .issue-card.info {{ border-left-color: #6c757d; }}
    .evidence {{ background: rgba(0,123,255,0.1); padding: 10px; border-radius: 4px; margin: 10px 0; }}
    .remediation {{ background: rgba(40,167,69,0.1); padding: 10px; border-radius: 4px; margin: 10px 0; }}
    table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid {theme_colors['border']}; }}
    th {{ background-color: {theme_colors['card_bg']}; }}
</style>"""
    
    def _format_body(self, report: 'Report') -> str:
        """Format HTML body content."""
        risk_score = report.get_risk_score()
        
        return f"""<body>
<div class="container">
    <div class="header">
        <h1>🔍 NetStealth Analyzer Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p><strong>Risk Score:</strong> {risk_score}/100</p>
    </div>
    
    {self._format_summary_html(report)}
    {self._format_issues_html(report)}
    {self._format_statistics_html(report)}
</div>"""
    
    def _format_summary_html(self, report: 'Report') -> str:
        """Format summary section in HTML."""
        summary = report.get_summary()
        severity_dist = summary['severity_distribution']
        
        return f"""<div class="summary-card">
        <h2>📊 Executive Summary</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td class="severity-critical">🔴 Critical</td><td>{severity_dist['critical']}</td></tr>
            <tr><td class="severity-high">🟠 High</td><td>{severity_dist['high']}</td></tr>
            <tr><td class="severity-medium">🟡 Medium</td><td>{severity_dist['medium']}</td></tr>
            <tr><td class="severity-low">🔵 Low</td><td>{severity_dist['low']}</td></tr>
            <tr><td class="severity-info">ℹ️ Info</td><td>{severity_dist['info']}</td></tr>
        </table>
    </div>"""
    
    def _format_issues_html(self, report: 'Report') -> str:
        """Format issues section in HTML."""
        if not report.issues:
            return '<div class="summary-card"><h2>📝 Issues</h2><p>No issues found.</p></div>'
        
        issues_html = ['<div class="summary-card"><h2>📝 Issues</h2>']
        
        for i, issue in enumerate(report.issues, 1):
            severity_value = issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity)
            category_value = issue.category.value if hasattr(issue.category, 'value') else str(issue.category)
            severity_class = severity_value.lower()
            issues_html.append(f'''
            <div class="issue-card {severity_class}">
                <h3>Issue #{i}: {issue.title}</h3>
                <p><strong>Category:</strong> {category_value}</p>
                <p><strong>Severity:</strong> {severity_value}</p>
                <p><strong>Confidence:</strong> {issue.confidence:.1%}</p>
                <p>{issue.description}</p>
                
                {self._format_evidence_html(issue.evidence)}
                {self._format_remediation_html(issue.remediation_suggestions)}
            </div>''')
        
        issues_html.append('</div>')
        return '\n'.join(issues_html)
    
    def _format_evidence_html(self, evidence_list: List) -> str:
        """Format evidence in HTML."""
        if not evidence_list:
            return ""
        
        html = ['<div class="evidence"><strong>Evidence:</strong><ul>']
        for evidence in evidence_list:
            html.append(f'<li>{evidence.description}: <code>{evidence.raw_data}</code></li>')
        html.append('</ul></div>')
        return '\n'.join(html)
    
    def _format_remediation_html(self, suggestions: List[str]) -> str:
        """Format remediation suggestions in HTML."""
        if not suggestions:
            return ""
        
        html = ['<div class="remediation"><strong>Remediation:</strong><ul>']
        for suggestion in suggestions:
            html.append(f'<li>{suggestion}</li>')
        html.append('</ul></div>')
        return '\n'.join(html)
    
    def _format_statistics_html(self, report: 'Report') -> str:
        """Format statistics section in HTML."""
        duration_str = f"{report.duration:.2f} seconds" if report.duration is not None else "N/A"
        
        return f"""<div class="summary-card">
        <h2>📈 Analysis Statistics</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Analysis Start</td><td>{report.start_time.strftime('%Y-%m-%d %H:%M:%S UTC') if report.start_time else 'N/A'}</td></tr>
            <tr><td>Analysis End</td><td>{report.end_time.strftime('%Y-%m-%d %H:%M:%S UTC') if report.end_time else 'N/A'}</td></tr>
            <tr><td>Duration</td><td>{duration_str}</td></tr>
            <tr><td>Total Issues</td><td>{report.issue_count}</td></tr>
        </table>
    </div>"""
    
    def _get_html_footer(self) -> str:
        """Get HTML document footer."""
        return """</body>
</html>"""


class YamlFormatter(ReportFormatter):
    """YAML report formatter for structured output."""
    
    def __init__(self, include_metadata: bool = True):
        """Initialize YAML formatter."""
        self.include_metadata = include_metadata
    
    def format(self, report: 'Report') -> str:
        """Format report as YAML."""
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML is required for YAML formatting. Install with: pip install pyyaml")
        
        data = {
            'netstealth_analyzer': {
                'version': '2.0.0',
                'report_generated': datetime.now().isoformat(),
                'format': 'yaml'
            },
            'summary': report.get_summary(),
            'issues': [self._format_issue_yaml(issue) for issue in report.issues]
        }
        
        if self.include_metadata:
            data['configuration'] = report.config
            data['statistics'] = report.statistics
        
        return yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)
    
    def _format_issue_yaml(self, issue: Issue) -> Dict[str, Any]:
        """Format a single issue for YAML output."""
        return {
            'id': issue.id,
            'title': issue.title,
            'description': issue.description,
            'category': issue.category.value,
            'severity': issue.severity.value,
            'confidence': float(issue.confidence),
            'timestamp': issue.timestamp.isoformat() if issue.timestamp else None,
            'evidence': [
                {
                    'type': evidence.evidence_type,
                    'description': evidence.description,
                    'data': evidence.data,
                    'metadata': evidence.metadata
                }
                for evidence in issue.evidence
            ],
            'remediation_suggestions': issue.remediation_suggestions,
            'metadata': issue.metadata
        }
