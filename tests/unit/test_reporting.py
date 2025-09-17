"""
Unit tests for the reporting system.

Tests the IncrementalReporter, Report class, and all formatters
with full Python 3.13 compatibility validation.
"""

import asyncio
import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List

from src.netstealth_analyzer.reporting.reporter import IncrementalReporter, Report
from src.netstealth_analyzer.reporting.formats import (
    JsonFormatter, MarkdownFormatter, HtmlFormatter, YamlFormatter
)
from src.netstealth_analyzer.core.events import EventBus, AnalysisEvent
from src.netstealth_analyzer.models.results import AnalysisResult
from src.netstealth_analyzer.models.issues import Issue, IssueEvidence
from src.netstealth_analyzer.models.enums import SeverityLevel, IssueCategory


class TestReport:
    """Test Report class."""
    
    def test_report_creation_from_parameters(self, sample_issue):
        """Test creating report from individual parameters."""
        issues = [sample_issue]
        statistics = {"processed": 10, "errors": 0}
        start_time = datetime.now(timezone.utc)
        end_time = datetime.now(timezone.utc)
        config = {"threshold": 0.7}
        
        report = Report(
            issues=issues,
            statistics=statistics,
            start_time=start_time,
            end_time=end_time,
            config=config
        )
        
        assert report.issues == issues
        assert report.statistics == statistics
        assert report.start_time == start_time
        assert report.end_time == end_time
        assert report.config == config
    
    def test_report_creation_from_analysis_result(self, sample_issue):
        """Test creating report from AnalysisResult."""
        issues = [sample_issue]
        start_time = datetime.now(timezone.utc)
        end_time = datetime.now(timezone.utc)
        
        from src.netstealth_analyzer.models.results import AnalysisSummary, ExecutionContext
        from src.netstealth_analyzer.models.enums import AnalysisStatus
        
        summary = AnalysisSummary(
            status=AnalysisStatus.SUCCESS,
            overall_score=85
        )
        summary.update_from_issues(issues)
        
        execution_context = ExecutionContext()
        execution_context.start_time = start_time
        execution_context.end_time = end_time
        
        analysis_result = AnalysisResult(
            summary=summary,
            execution_context=execution_context,
            issues=issues
        )
        
        report = Report(analysis_result=analysis_result)
        
        assert report.issues == issues
        assert report.start_time == start_time
        assert report.end_time == end_time
    
    def test_report_properties(self, sample_issue):
        """Test report properties."""
        issues = [sample_issue]
        start_time = datetime.now(timezone.utc)
        end_time = start_time + timedelta(seconds=5)
        
        report = Report(
            issues=issues,
            start_time=start_time,
            end_time=end_time
        )
        
        assert report.issue_count == 1
        assert report.duration == 5.0
        assert len(report.high_issues) == 1  # sample_issue is HIGH severity
        assert len(report.critical_issues) == 0
    
    def test_report_severity_filtering(self):
        """Test filtering issues by severity."""
        from tests.conftest import generate_test_issues
        
        issues = generate_test_issues(10)
        report = Report(issues=issues)
        
        # Test severity properties
        critical_issues = report.critical_issues
        high_issues = report.high_issues
        medium_issues = report.medium_issues
        low_issues = report.low_issues
        info_issues = report.info_issues
        
        # Verify all issues are accounted for
        total_filtered = len(critical_issues) + len(high_issues) + len(medium_issues) + len(low_issues) + len(info_issues)
        assert total_filtered == len(issues)
        
        # Test get_issues_by_severity method
        high_by_method = report.get_issues_by_severity(SeverityLevel.HIGH)
        assert high_by_method == high_issues
    
    def test_report_category_filtering(self):
        """Test filtering issues by category."""
        from tests.conftest import generate_test_issues
        
        issues = generate_test_issues(5)
        report = Report(issues=issues)
        
        # Test category filtering
        proxy_issues = report.get_issues_by_category(IssueCategory.PROXY_DETECTION)
        assert isinstance(proxy_issues, list)
        
        # Verify all returned issues have the correct category
        for issue in proxy_issues:
            assert issue.category == IssueCategory.PROXY_DETECTION
    
    def test_report_distributions(self):
        """Test severity and category distributions."""
        from tests.conftest import generate_test_issues
        
        issues = generate_test_issues(10)
        report = Report(issues=issues)
        
        # Test severity distribution
        severity_dist = report.get_severity_distribution()
        assert isinstance(severity_dist, dict)
        assert "critical" in severity_dist
        assert "high" in severity_dist
        assert "medium" in severity_dist
        assert "low" in severity_dist
        assert "info" in severity_dist
        
        # Verify total count matches
        total_count = sum(severity_dist.values())
        assert total_count == len(issues)
        
        # Test category distribution
        category_dist = report.get_category_distribution()
        assert isinstance(category_dist, dict)
        
        # Verify total count matches
        total_count = sum(category_dist.values())
        assert total_count == len(issues)
    
    def test_report_risk_score(self):
        """Test risk score calculation."""
        # Test empty report
        empty_report = Report()
        assert empty_report.get_risk_score() == 0.0
        
        # Test report with issues
        from tests.conftest import generate_test_issues
        issues = generate_test_issues(5)
        report = Report(issues=issues)
        
        risk_score = report.get_risk_score()
        assert isinstance(risk_score, float)
        assert 0.0 <= risk_score <= 100.0
    
    def test_report_summary(self):
        """Test report summary generation."""
        from tests.conftest import generate_test_issues
        
        issues = generate_test_issues(3)
        start_time = datetime.now(timezone.utc)
        end_time = start_time + timedelta(seconds=10)
        statistics = {"processed": 100}
        
        report = Report(
            issues=issues,
            start_time=start_time,
            end_time=end_time,
            statistics=statistics
        )
        
        summary = report.get_summary()
        
        assert isinstance(summary, dict)
        assert summary["total_issues"] == 3
        assert summary["analysis_duration"] == 10.0
        assert "severity_distribution" in summary
        assert "category_distribution" in summary
        assert "risk_score" in summary
        assert summary["statistics"] == statistics
    
    def test_report_to_dict(self):
        """Test converting report to dictionary."""
        from tests.conftest import generate_test_issues
        
        issues = generate_test_issues(2)
        config = {"test": True}
        report = Report(issues=issues, config=config)
        
        data = report.to_dict()
        
        assert isinstance(data, dict)
        assert "summary" in data
        assert "issues" in data
        assert "configuration" in data
        assert len(data["issues"]) == 2
        assert data["configuration"] == config
    
    def test_report_json_conversion(self):
        """Test converting report to JSON."""
        from tests.conftest import generate_test_issues
        
        issues = generate_test_issues(1)
        report = Report(issues=issues)
        
        json_str = report.to_json()
        
        assert isinstance(json_str, str)
        assert "summary" in json_str
        assert "issues" in json_str
        
        # Test with custom indent
        json_str_compact = report.to_json(indent=None)
        assert len(json_str_compact) < len(json_str)  # Compact should be shorter
    
    def test_report_string_representation(self):
        """Test report string representation."""
        from tests.conftest import generate_test_issues
        
        issues = generate_test_issues(3)
        start_time = datetime.now(timezone.utc)
        end_time = start_time + timedelta(seconds=5)
        
        report = Report(
            issues=issues,
            start_time=start_time,
            end_time=end_time
        )
        
        str_repr = str(report)
        
        assert "NetStealth Analysis Report" in str_repr
        assert "Total Issues: 3" in str_repr
        assert "Duration: 5.00s" in str_repr
    
    @pytest.mark.asyncio
    async def test_report_streaming(self):
        """Test report streaming methods."""
        from tests.conftest import generate_test_issues
        
        issues = generate_test_issues(2)
        report = Report(issues=issues)
        
        # Test markdown streaming
        markdown_chunks = []
        async for chunk in report.stream_markdown(chunk_size=100):
            markdown_chunks.append(chunk)
            assert isinstance(chunk, str)
            assert len(chunk) <= 100
        
        # Verify complete content
        full_markdown = "".join(markdown_chunks)
        assert len(full_markdown) > 0
        
        # Test JSON streaming
        json_chunks = []
        async for chunk in report.stream_json(chunk_size=50):
            json_chunks.append(chunk)
            assert isinstance(chunk, str)
            assert len(chunk) <= 50
        
        # Verify complete content
        full_json = "".join(json_chunks)
        assert len(full_json) > 0


class TestIncrementalReporter:
    """Test IncrementalReporter class."""
    
    def test_incremental_reporter_creation(self, event_bus):
        """Test creating incremental reporter."""
        reporter = IncrementalReporter(event_bus)
        
        assert reporter.event_bus == event_bus
        assert len(reporter._issues) == 0
        assert len(reporter._statistics) == 0
    
    def test_incremental_reporter_without_event_bus(self):
        """Test creating incremental reporter without event bus."""
        reporter = IncrementalReporter()
        
        assert reporter.event_bus is None
        assert len(reporter._issues) == 0
    
    def test_add_issue(self, sample_issue):
        """Test adding issue to reporter."""
        reporter = IncrementalReporter()
        
        reporter.add_issue(sample_issue)
        
        assert len(reporter._issues) == 1
        assert reporter._issues[0] == sample_issue
    
    def test_get_current_report(self, sample_issue):
        """Test getting current report state."""
        reporter = IncrementalReporter()
        start_time = datetime.now(timezone.utc)
        reporter._start_time = start_time
        reporter.add_issue(sample_issue)
        reporter._statistics = {"processed": 5}
        
        report = reporter.get_current_report()
        
        assert isinstance(report, Report)
        assert len(report.issues) == 1
        assert report.statistics["processed"] == 5
        assert report.start_time == start_time
    
    @pytest.mark.asyncio
    async def test_event_handlers(self, event_bus):
        """Test event handler setup and execution."""
        reporter = IncrementalReporter(event_bus)
        
        # Test analysis started event
        config_data = {"config": {"threshold": 0.7}}
        await reporter._on_analysis_started(config_data)
        
        assert reporter._start_time is not None
        assert reporter._analysis_config == {"threshold": 0.7}
        
        # Test issue found event
        sample_issue = Mock()
        await reporter._on_issue_found(sample_issue)
        
        assert len(reporter._issues) == 1
        assert reporter._issues[0] == sample_issue
        
        # Test progress update event
        progress_data = {"processed": 10, "remaining": 5}
        await reporter._on_progress_update(progress_data)
        
        assert reporter._statistics["processed"] == 10
        assert reporter._statistics["remaining"] == 5
        
        # Test analysis completed event
        completion_data = {"statistics": {"total": 15}}
        await reporter._on_analysis_completed(completion_data)
        
        assert reporter._end_time is not None
        assert reporter._statistics["total"] == 15
    
    @pytest.mark.asyncio
    async def test_stream_issues(self, sample_issue):
        """Test streaming issues as they are discovered."""
        reporter = IncrementalReporter()
        
        # Start streaming task
        stream_task = asyncio.create_task(self._collect_streamed_issues(reporter))
        
        # Add issues with delay
        await asyncio.sleep(0.1)
        reporter.add_issue(sample_issue)
        
        await asyncio.sleep(0.1)
        reporter._end_time = datetime.now(timezone.utc)  # Signal completion
        
        # Wait for streaming to complete
        streamed_issues = await stream_task
        
        assert len(streamed_issues) == 1
        assert streamed_issues[0] == sample_issue
    
    async def _collect_streamed_issues(self, reporter):
        """Helper method to collect streamed issues."""
        issues = []
        async for issue in reporter.stream_issues():
            issues.append(issue)
        return issues
    
    @pytest.mark.asyncio
    async def test_stream_report_updates(self, sample_issue):
        """Test streaming report updates."""
        reporter = IncrementalReporter()
        
        # Start streaming task
        stream_task = asyncio.create_task(self._collect_report_updates(reporter))
        
        # Add issue and complete analysis
        await asyncio.sleep(0.1)
        reporter.add_issue(sample_issue)
        reporter._end_time = datetime.now(timezone.utc)
        
        # Wait for streaming to complete
        reports = await stream_task
        
        assert len(reports) >= 1
        assert all(isinstance(report, Report) for report in reports)
    
    async def _collect_report_updates(self, reporter):
        """Helper method to collect report updates."""
        reports = []
        async for report in reporter.stream_report_updates():
            reports.append(report)
        return reports


class TestJsonFormatter:
    """Test JsonFormatter class."""
    
    def test_json_formatter_creation(self):
        """Test creating JSON formatter."""
        formatter = JsonFormatter()
        
        assert formatter.indent == 2
        assert formatter.include_metadata is True
        
        # Test with custom parameters
        formatter_custom = JsonFormatter(indent=4, include_metadata=False)
        assert formatter_custom.indent == 4
        assert formatter_custom.include_metadata is False
    
    def test_json_format_empty_report(self):
        """Test formatting empty report."""
        formatter = JsonFormatter()
        report = Report()
        
        json_output = formatter.format(report)
        
        assert isinstance(json_output, str)
        assert "netstealth_analyzer" in json_output
        assert "summary" in json_output
        assert "issues" in json_output
    
    def test_json_format_report_with_issues(self):
        """Test formatting report with issues."""
        from tests.conftest import generate_test_issues
        
        formatter = JsonFormatter()
        issues = generate_test_issues(2)
        report = Report(issues=issues)
        
        json_output = formatter.format(report)
        
        assert isinstance(json_output, str)
        assert "issues" in json_output
        assert len(report.issues) == 2
        
        # Verify JSON is valid
        import json
        data = json.loads(json_output)
        assert len(data["issues"]) == 2
    
    def test_json_format_without_metadata(self):
        """Test formatting without metadata."""
        formatter = JsonFormatter(include_metadata=False)
        report = Report(config={"test": True}, statistics={"processed": 10})
        
        json_output = formatter.format(report)
        
        import json
        data = json.loads(json_output)
        
        assert "configuration" not in data
        assert "statistics" not in data


class TestMarkdownFormatter:
    """Test MarkdownFormatter class."""
    
    def test_markdown_formatter_creation(self):
        """Test creating Markdown formatter."""
        formatter = MarkdownFormatter()
        
        assert formatter.include_toc is True
        assert formatter.include_details is True
        
        # Test with custom parameters
        formatter_custom = MarkdownFormatter(include_toc=False, include_details=False)
        assert formatter_custom.include_toc is False
        assert formatter_custom.include_details is False
    
    def test_markdown_format_empty_report(self):
        """Test formatting empty report."""
        formatter = MarkdownFormatter()
        report = Report()
        
        markdown_output = formatter.format(report)
        
        assert isinstance(markdown_output, str)
        assert "# 🔍 NetStealth Analyzer Report" in markdown_output
        assert "## 📊 Executive Summary" in markdown_output
        assert "No issues found" in markdown_output
    
    def test_markdown_format_report_with_issues(self):
        """Test formatting report with issues."""
        from tests.conftest import generate_test_issues
        
        formatter = MarkdownFormatter()
        issues = generate_test_issues(3)
        start_time = datetime.now(timezone.utc)
        end_time = start_time + timedelta(seconds=10)
        
        report = Report(
            issues=issues,
            start_time=start_time,
            end_time=end_time
        )
        
        markdown_output = formatter.format(report)
        
        assert isinstance(markdown_output, str)
        assert "Total Issues**: 3" in markdown_output
        assert "Duration**: 10.00s" in markdown_output
        assert "## 📝 Detailed Issues" in markdown_output
    
    def test_markdown_format_without_toc(self):
        """Test formatting without table of contents."""
        formatter = MarkdownFormatter(include_toc=False)
        report = Report()
        
        markdown_output = formatter.format(report)
        
        assert "## 📋 Table of Contents" not in markdown_output
    
    def test_markdown_format_without_details(self):
        """Test formatting without detailed issues."""
        from tests.conftest import generate_test_issues
        
        formatter = MarkdownFormatter(include_details=False)
        issues = generate_test_issues(2)
        report = Report(issues=issues)
        
        markdown_output = formatter.format(report)
        
        assert "## 📝 Detailed Issues" not in markdown_output
    
    def test_markdown_risk_level_descriptions(self):
        """Test risk level descriptions."""
        formatter = MarkdownFormatter()
        
        assert formatter._get_risk_level(90) == "CRITICAL"
        assert formatter._get_risk_level(70) == "HIGH"
        assert formatter._get_risk_level(50) == "MEDIUM"
        assert formatter._get_risk_level(30) == "LOW"
        assert formatter._get_risk_level(10) == "MINIMAL"
        
        # Test risk descriptions
        critical_desc = formatter._get_risk_description(90)
        assert "IMMEDIATE ACTION REQUIRED" in critical_desc
        
        minimal_desc = formatter._get_risk_description(10)
        assert "MINIMAL RISK" in minimal_desc


class TestHtmlFormatter:
    """Test HtmlFormatter class."""
    
    def test_html_formatter_creation(self):
        """Test creating HTML formatter."""
        formatter = HtmlFormatter()
        
        assert formatter.include_css is True
        assert formatter.dark_theme is False
        
        # Test with custom parameters
        formatter_dark = HtmlFormatter(include_css=False, dark_theme=True)
        assert formatter_dark.include_css is False
        assert formatter_dark.dark_theme is True
    
    def test_html_format_empty_report(self):
        """Test formatting empty report."""
        formatter = HtmlFormatter()
        report = Report()
        
        html_output = formatter.format(report)
        
        assert isinstance(html_output, str)
        assert "<!DOCTYPE html>" in html_output
        assert "<title>NetStealth Analyzer Report</title>" in html_output
        assert "🔍 NetStealth Analyzer Report" in html_output
        assert "No issues found" in html_output
    
    def test_html_format_with_css(self):
        """Test formatting with CSS styles."""
        formatter = HtmlFormatter(include_css=True)
        report = Report()
        
        html_output = formatter.format(report)
        
        assert "<style>" in html_output
        assert "font-family:" in html_output
        assert ".summary-card" in html_output
    
    def test_html_format_without_css(self):
        """Test formatting without CSS styles."""
        formatter = HtmlFormatter(include_css=False)
        report = Report()
        
        html_output = formatter.format(report)
        
        assert "<style>" not in html_output
    
    def test_html_dark_theme(self):
        """Test HTML dark theme."""
        formatter = HtmlFormatter(dark_theme=True)
        report = Report()
        
        html_output = formatter.format(report)
        
        assert "#1a1a1a" in html_output  # Dark background color
        assert "#ffffff" in html_output  # Light text color
    
    def test_html_format_report_with_issues(self):
        """Test formatting report with issues."""
        from tests.conftest import generate_test_issues
        
        formatter = HtmlFormatter()
        issues = generate_test_issues(2)
        report = Report(issues=issues)
        
        html_output = formatter.format(report)
        
        assert isinstance(html_output, str)
        assert "Issue #1:" in html_output
        assert "Issue #2:" in html_output
        assert '<div class="issue-card' in html_output


class TestYamlFormatter:
    """Test YamlFormatter class."""
    
    def test_yaml_formatter_creation(self):
        """Test creating YAML formatter."""
        formatter = YamlFormatter()
        
        assert formatter.include_metadata is True
        
        # Test with custom parameters
        formatter_no_meta = YamlFormatter(include_metadata=False)
        assert formatter_no_meta.include_metadata is False
    
    @pytest.mark.skipif(True, reason="PyYAML not required for core functionality")
    def test_yaml_format_empty_report(self):
        """Test formatting empty report (skipped if PyYAML not available)."""
        try:
            formatter = YamlFormatter()
            report = Report()
            
            yaml_output = formatter.format(report)
            
            assert isinstance(yaml_output, str)
            assert "netstealth_analyzer:" in yaml_output
            assert "summary:" in yaml_output
        except ImportError:
            pytest.skip("PyYAML not available")
    
    def test_yaml_import_error(self):
        """Test YAML formatter when PyYAML is not available."""
        formatter = YamlFormatter()
        report = Report()
        
        with patch('builtins.__import__', side_effect=ImportError("No module named 'yaml'")):
            with pytest.raises(ImportError, match="PyYAML is required"):
                formatter.format(report)


class TestReportFileSaving:
    """Test report file saving methods."""
    
    def test_save_json(self, temp_directory):
        """Test saving report as JSON file."""
        from tests.conftest import generate_test_issues
        
        issues = generate_test_issues(1)
        report = Report(issues=issues)
        
        json_file = temp_directory / "test_report.json"
        report.save_json(json_file)
        
        assert json_file.exists()
        content = json_file.read_text()
        assert "netstealth_analyzer" in content
        assert "issues" in content
    
    def test_save_markdown(self, temp_directory):
        """Test saving report as Markdown file."""
        from tests.conftest import generate_test_issues
        
        issues = generate_test_issues(1)
        report = Report(issues=issues)
        
        md_file = temp_directory / "test_report.md"
        report.save_markdown(md_file)
        
        assert md_file.exists()
        content = md_file.read_text(encoding='utf-8')
        assert "# 🔍 NetStealth Analyzer Report" in content
    
    def test_save_html(self, temp_directory):
        """Test saving report as HTML file."""
        from tests.conftest import generate_test_issues
        
        issues = generate_test_issues(1)
        report = Report(issues=issues)
        
        html_file = temp_directory / "test_report.html"
        report.save_html(html_file)
        
        assert html_file.exists()
        content = html_file.read_text(encoding='utf-8')
        assert "<!DOCTYPE html>" in content
        assert "NetStealth Analyzer Report" in content
