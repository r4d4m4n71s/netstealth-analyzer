"""
Core reporting classes for NetStealth Analyzer.

This module provides the main reporting functionality including incremental report generation,
streaming support, and multiple output formats with full async support.
"""

import asyncio
import time
from typing import Any, AsyncIterator, Dict, List, Optional, Union
from datetime import datetime, timezone
from pathlib import Path

from ..models.results import AnalysisResult
from ..models.issues import Issue
from ..models.enums import SeverityLevel, IssueCategory
from ..core.events import EventBus, AnalysisEvent


class IncrementalReporter:
    """
    Incremental reporter that generates reports as analysis progresses.
    
    Supports real-time report generation, streaming output, and multiple formats
    with async processing for optimal performance.
    """
    
    def __init__(self, event_bus: Optional[EventBus] = None):
        """Initialize incremental reporter."""
        self.event_bus = event_bus
        self._issues: List[Issue] = []
        self._statistics: Dict[str, Any] = {}
        self._start_time: Optional[datetime] = None
        self._end_time: Optional[datetime] = None
        self._analysis_config: Dict[str, Any] = {}
        
        # Subscribe to analysis events if event bus provided
        if self.event_bus:
            self._setup_event_handlers()
    
    def _setup_event_handlers(self) -> None:
        """Set up event handlers for analysis events."""
        self.event_bus.subscribe(AnalysisEvent.ANALYSIS_STARTED, self._on_analysis_started)
        self.event_bus.subscribe(AnalysisEvent.ISSUE_FOUND, self._on_issue_found)
        self.event_bus.subscribe(AnalysisEvent.ANALYSIS_COMPLETED, self._on_analysis_completed)
        self.event_bus.subscribe(AnalysisEvent.PROGRESS_UPDATE, self._on_progress_update)
    
    async def _on_analysis_started(self, data: Dict[str, Any]) -> None:
        """Handle analysis started event."""
        self._start_time = datetime.now(timezone.utc)
        self._analysis_config = data.get('config', {})
        self._issues.clear()
        self._statistics.clear()
    
    async def _on_issue_found(self, issue: Issue) -> None:
        """Handle issue found event."""
        self._issues.append(issue)
    
    async def _on_analysis_completed(self, data: Dict[str, Any]) -> None:
        """Handle analysis completed event."""
        self._end_time = datetime.now(timezone.utc)
        self._statistics.update(data.get('statistics', {}))
    
    async def _on_progress_update(self, data: Dict[str, Any]) -> None:
        """Handle progress update event."""
        # Update internal statistics with progress data
        self._statistics.update(data)
    
    def add_issue(self, issue: Issue) -> None:
        """Add an issue to the report."""
        self._issues.append(issue)
    
    def get_current_report(self) -> 'Report':
        """Get current report state."""
        return Report(
            issues=self._issues.copy(),
            statistics=self._statistics.copy(),
            start_time=self._start_time,
            end_time=self._end_time,
            config=self._analysis_config.copy()
        )
    
    async def stream_issues(self) -> AsyncIterator[Issue]:
        """Stream issues as they are discovered."""
        yielded_count = 0
        
        while True:
            # Yield any new issues
            while yielded_count < len(self._issues):
                yield self._issues[yielded_count]
                yielded_count += 1
            
            # If analysis is complete, stop streaming
            if self._end_time is not None:
                break
            
            # Wait a bit before checking for new issues
            await asyncio.sleep(0.1)
    
    async def stream_report_updates(self) -> AsyncIterator['Report']:
        """Stream report updates as analysis progresses."""
        last_update_time = time.time()
        
        while True:
            current_time = time.time()
            
            # Emit report update every second or when analysis completes
            if current_time - last_update_time >= 1.0 or self._end_time is not None:
                yield self.get_current_report()
                last_update_time = current_time
                
                # If analysis is complete, stop streaming
                if self._end_time is not None:
                    break
            
            await asyncio.sleep(0.1)


class Report:
    """
    Analysis report with multiple output format support.
    
    Provides comprehensive reporting capabilities including summary statistics,
    issue categorization, and multiple export formats.
    """
    
    def __init__(
        self,
        issues: Optional[List[Issue]] = None,
        statistics: Optional[Dict[str, Any]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        config: Optional[Dict[str, Any]] = None,
        analysis_result: Optional[AnalysisResult] = None
    ):
        """Initialize report."""
        if analysis_result:
            # Initialize from AnalysisResult
            self.issues = analysis_result.issues
            self.statistics = analysis_result.processing_stats.get_performance_summary() if analysis_result.processing_stats else {}
            self.start_time = analysis_result.execution_context.start_time
            self.end_time = analysis_result.execution_context.end_time
            self.config = analysis_result.execution_context.configuration_summary
        else:
            # Initialize from individual parameters
            self.issues = issues or []
            self.statistics = statistics or {}
            self.start_time = start_time
            self.end_time = end_time
            self.config = config or {}
    
    @property
    def duration(self) -> Optional[float]:
        """Get analysis duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    @property
    def issue_count(self) -> int:
        """Get total number of issues."""
        return len(self.issues)
    
    @property
    def critical_issues(self) -> List[Issue]:
        """Get critical severity issues."""
        return [issue for issue in self.issues if issue.severity == SeverityLevel.CRITICAL]
    
    @property
    def high_issues(self) -> List[Issue]:
        """Get high severity issues."""
        return [issue for issue in self.issues if issue.severity == SeverityLevel.HIGH]
    
    @property
    def medium_issues(self) -> List[Issue]:
        """Get medium severity issues."""
        return [issue for issue in self.issues if issue.severity == SeverityLevel.MEDIUM]
    
    @property
    def low_issues(self) -> List[Issue]:
        """Get low severity issues."""
        return [issue for issue in self.issues if issue.severity == SeverityLevel.LOW]
    
    @property
    def info_issues(self) -> List[Issue]:
        """Get info severity issues."""
        return [issue for issue in self.issues if issue.severity == SeverityLevel.INFO]
    
    def get_issues_by_category(self, category: IssueCategory) -> List[Issue]:
        """Get issues by category."""
        return [issue for issue in self.issues if issue.category == category]
    
    def get_issues_by_severity(self, severity: SeverityLevel) -> List[Issue]:
        """Get issues by severity level."""
        return [issue for issue in self.issues if issue.severity == severity]
    
    def get_severity_distribution(self) -> Dict[str, int]:
        """Get distribution of issues by severity."""
        distribution = {
            'critical': len(self.critical_issues),
            'high': len(self.high_issues),
            'medium': len(self.medium_issues),
            'low': len(self.low_issues),
            'info': len(self.info_issues)
        }
        return distribution
    
    def get_category_distribution(self) -> Dict[str, int]:
        """Get distribution of issues by category."""
        distribution = {}
        for issue in self.issues:
            # Handle both enum and string categories
            if hasattr(issue.category, 'value'):
                category_name = issue.category.value
            else:
                category_name = str(issue.category)
            distribution[category_name] = distribution.get(category_name, 0) + 1
        return distribution
    
    def get_risk_score(self) -> float:
        """Calculate overall risk score (0-100)."""
        if not self.issues:
            return 0.0
        
        # Weight issues by severity
        severity_weights = {
            SeverityLevel.CRITICAL: 10.0,
            SeverityLevel.HIGH: 7.0,
            SeverityLevel.MEDIUM: 4.0,
            SeverityLevel.LOW: 2.0,
            SeverityLevel.INFO: 1.0
        }
        
        total_weight = 0.0
        for issue in self.issues:
            weight = severity_weights.get(issue.severity, 1.0)
            confidence_multiplier = issue.confidence
            total_weight += weight * confidence_multiplier
        
        # Normalize to 0-100 scale (assuming max 20 critical issues would be 100)
        max_possible_score = 20 * severity_weights[SeverityLevel.CRITICAL]
        risk_score = min(100.0, (total_weight / max_possible_score) * 100.0)
        
        return round(risk_score, 1)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get report summary."""
        return {
            'total_issues': self.issue_count,
            'severity_distribution': self.get_severity_distribution(),
            'category_distribution': self.get_category_distribution(),
            'risk_score': self.get_risk_score(),
            'analysis_duration': self.duration,
            'analysis_start_time': self.start_time.isoformat() if self.start_time else None,
            'analysis_end_time': self.end_time.isoformat() if self.end_time else None,
            'statistics': self.statistics
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            'summary': self.get_summary(),
            'issues': [issue.to_dict() for issue in self.issues],
            'configuration': self.config
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert report to JSON string."""
        from .formats import JsonFormatter
        formatter = JsonFormatter(indent=indent)
        return formatter.format(self)
    
    def to_markdown(self) -> str:
        """Convert report to Markdown format."""
        from .formats import MarkdownFormatter
        formatter = MarkdownFormatter()
        return formatter.format(self)
    
    def to_html(self) -> str:
        """Convert report to HTML format."""
        from .formats import HtmlFormatter
        formatter = HtmlFormatter()
        return formatter.format(self)
    
    def to_yaml(self) -> str:
        """Convert report to YAML format."""
        from .formats import YamlFormatter
        formatter = YamlFormatter()
        return formatter.format(self)
    
    def save_json(self, path: Union[str, Path], indent: int = 2) -> None:
        """Save report as JSON file."""
        path = Path(path)
        path.write_text(self.to_json(indent=indent), encoding='utf-8')
    
    def save_markdown(self, path: Union[str, Path]) -> None:
        """Save report as Markdown file."""
        path = Path(path)
        path.write_text(self.to_markdown(), encoding='utf-8')
    
    def save_html(self, path: Union[str, Path]) -> None:
        """Save report as HTML file."""
        path = Path(path)
        path.write_text(self.to_html(), encoding='utf-8')
    
    def save_yaml(self, path: Union[str, Path]) -> None:
        """Save report as YAML file."""
        path = Path(path)
        path.write_text(self.to_yaml(), encoding='utf-8')
    
    async def stream_markdown(self, chunk_size: int = 1024) -> AsyncIterator[str]:
        """Stream report as Markdown chunks."""
        markdown_content = self.to_markdown()
        
        for i in range(0, len(markdown_content), chunk_size):
            chunk = markdown_content[i:i + chunk_size]
            yield chunk
            await asyncio.sleep(0)  # Allow other tasks to run
    
    async def stream_json(self, chunk_size: int = 1024) -> AsyncIterator[str]:
        """Stream report as JSON chunks."""
        json_content = self.to_json()
        
        for i in range(0, len(json_content), chunk_size):
            chunk = json_content[i:i + chunk_size]
            yield chunk
            await asyncio.sleep(0)  # Allow other tasks to run
    
    def __str__(self) -> str:
        """String representation of report."""
        summary = self.get_summary()
        return (
            f"NetStealth Analysis Report\n"
            f"========================\n"
            f"Total Issues: {summary['total_issues']}\n"
            f"Risk Score: {summary['risk_score']}/100\n"
            f"Duration: {summary['analysis_duration']:.2f}s\n"
            f"Critical: {summary['severity_distribution']['critical']}, "
            f"High: {summary['severity_distribution']['high']}, "
            f"Medium: {summary['severity_distribution']['medium']}, "
            f"Low: {summary['severity_distribution']['low']}, "
            f"Info: {summary['severity_distribution']['info']}"
        )
