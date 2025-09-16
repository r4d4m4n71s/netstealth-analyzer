"""
Core analyzer for network stealth operations.

This module provides the main NetStealthAnalyzer class that orchestrates
the analysis of various log sources to detect stealth issues and provide
comprehensive reports.
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .models import (
    AnalysisConfig,
    AnalysisResult,
    AnalysisSummary,
    CriticalIssue,
    IssueCategory,
    LogFormat,
    LogSource,
    NetworkHop,
    PerformanceMetrics,
    SeverityLevel,
    TLSInfo,
    RiskLevel,
)
from .parsers.mitmproxy import MitmproxyParser
from .parsers.poc import PocExecutionParser
from .parsers.har import HarParser
from .parsers.browser import BrowserLogParser
from .detectors.tls import TLSDetector
from .detectors.proxy import ProxyDetector
from .detectors.browser import BrowserDetector
from .detectors.network import NetworkDetector
from .reports.summary import SummaryReportGenerator
from .utils import load_config, setup_logging


class NetStealthAnalyzer:
    """
    Main analyzer for network stealth operations.
    
    This class orchestrates the analysis of multiple log sources to detect
    TLS fingerprint issues, proxy indicators, browser configuration problems,
    and other stealth-related issues.
    """
    
    def __init__(
        self,
        config: Optional[Union[AnalysisConfig, Dict[str, Any], str, Path]] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the NetStealth Analyzer.
        
        Args:
            config: Analysis configuration (config object, dict, or path to config file)
            logger: Optional logger instance
        """
        # Setup logging
        self.logger = logger or setup_logging(__name__)
        
        # Load and validate configuration
        if config is None:
            self.config = AnalysisConfig()
        elif isinstance(config, AnalysisConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = AnalysisConfig(**config)
        elif isinstance(config, (str, Path)):
            self.config = load_config(Path(config))
        else:
            raise ValueError(f"Invalid config type: {type(config)}")
        
        # Initialize parsers
        self.parsers = {
            LogFormat.MITMPROXY: MitmproxyParser(),
            LogFormat.POC_EXECUTION: PocExecutionParser(),
            LogFormat.HAR: HarParser(),
            LogFormat.BROWSER_CONSOLE: BrowserLogParser(),
            LogFormat.CHROME_DEBUG: BrowserLogParser(),
        }
        
        # Initialize detectors
        self.detectors = {
            IssueCategory.TLS_FINGERPRINT: TLSDetector(self.config),
            IssueCategory.PROXY_DETECTION: ProxyDetector(self.config),
            IssueCategory.BROWSER_CONFIG: BrowserDetector(self.config),
            IssueCategory.NETWORK_ANOMALY: NetworkDetector(self.config),
        }
        
        # Initialize report generator
        self.report_generator = SummaryReportGenerator(self.config)
        
        # Analysis state
        self.analysis_start_time: Optional[float] = None
        self.parsed_data: Dict[str, Any] = {}
    
    def analyze(
        self,
        log_sources: Union[str, Path, List[Union[str, Path, LogSource]]],
        config_override: Optional[Dict[str, Any]] = None
    ) -> AnalysisResult:
        """
        Analyze log sources and return comprehensive results.
        
        Args:
            log_sources: Single log file path or list of log sources
            config_override: Optional config overrides for this analysis
            
        Returns:
            AnalysisResult: Comprehensive analysis results
        """
        self.analysis_start_time = time.time()
        self.logger.info("Starting network stealth analysis")
        
        # Apply config overrides if provided
        if config_override:
            config_dict = self.config.model_dump()
            config_dict.update(config_override)
            analysis_config = AnalysisConfig(**config_dict)
        else:
            analysis_config = self.config
        
        try:
            # Normalize log sources
            normalized_sources = self._normalize_log_sources(log_sources)
            self.logger.info(f"Processing {len(normalized_sources)} log sources")
            
            # Parse all log sources
            all_parsed_data = self._parse_log_sources(normalized_sources)
            
            # Run detection analysis
            all_issues = self._run_detectors(all_parsed_data)
            
            # Build network trace
            network_trace = self._build_network_trace(all_parsed_data)
            
            # Calculate performance metrics
            performance_metrics = self._calculate_performance_metrics(all_parsed_data)
            
            # Generate analysis summary
            summary = self._generate_summary(all_issues, network_trace, performance_metrics)
            
            # Optional features
            session_timeline = None
            fingerprint_comparison = None
            remediation_suggestions = []
            
            if analysis_config.session_timeline:
                session_timeline = self._generate_timeline(all_parsed_data)
            
            if analysis_config.fingerprint_comparison:
                fingerprint_comparison = self._compare_fingerprints(all_parsed_data)
            
            if analysis_config.auto_remediation:
                remediation_suggestions = self._generate_remediation(all_issues)
            
            # Create final result
            result = AnalysisResult(
                summary=summary,
                critical_issues=all_issues,
                network_trace=network_trace,
                performance_metrics=performance_metrics,
                config_used=analysis_config,
                log_sources=normalized_sources,
                session_timeline=session_timeline,
                fingerprint_comparison=fingerprint_comparison,
                remediation_suggestions=remediation_suggestions,
                raw_log_data=all_parsed_data if analysis_config.include_raw_data else {}
            )
            
            analysis_duration = (time.time() - self.analysis_start_time) * 1000
            result.summary.analysis_duration_ms = analysis_duration
            
            self.logger.info(f"Analysis completed in {analysis_duration:.2f}ms")
            self.logger.info(f"Found {len(all_issues)} issues across {len(normalized_sources)} sources")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            # Return partial result with error information
            error_issue = CriticalIssue(
                id="ANALYZER_ERROR",
                category=IssueCategory.PERFORMANCE,
                severity=SeverityLevel.CRITICAL,
                title="Analysis Failed",
                description=f"Analyzer encountered an error: {str(e)}",
                impact_score=100
            )
            
            summary = AnalysisSummary(
                status="FAILED",
                overall_score=0,
                critical_issues_count=1,
                total_issues_count=1,
                timestamp=datetime.now()
            )
            
            return AnalysisResult(
                summary=summary,
                critical_issues=[error_issue],
                network_trace=[],
                performance_metrics=PerformanceMetrics(),
                config_used=analysis_config,
                log_sources=[]
            )
    
    def analyze_single_file(
        self,
        log_file: Union[str, Path],
        log_format: Optional[LogFormat] = None
    ) -> AnalysisResult:
        """
        Convenience method to analyze a single log file.
        
        Args:
            log_file: Path to log file
            log_format: Optional log format (auto-detected if not provided)
            
        Returns:
            AnalysisResult: Analysis results
        """
        log_path = Path(log_file)
        
        # Auto-detect format if not provided
        if log_format is None:
            log_format = self._detect_log_format(log_path)
        
        log_source = LogSource(
            path=log_path,
            format=log_format,
            priority=1
        )
        
        return self.analyze([log_source])
    
    def _normalize_log_sources(
        self,
        sources: Union[str, Path, List[Union[str, Path, LogSource]]]
    ) -> List[LogSource]:
        """Normalize various input formats to LogSource objects."""
        if isinstance(sources, (str, Path)):
            # Single file path
            path = Path(sources)
            return [LogSource(
                path=path,
                format=self._detect_log_format(path),
                priority=1
            )]
        
        normalized = []
        for source in sources:
            if isinstance(source, LogSource):
                normalized.append(source)
            elif isinstance(source, (str, Path)):
                path = Path(source)
                normalized.append(LogSource(
                    path=path,
                    format=self._detect_log_format(path),
                    priority=1
                ))
            else:
                self.logger.warning(f"Skipping invalid log source: {source}")
        
        # Sort by priority
        return sorted(normalized, key=lambda x: x.priority)
    
    def _detect_log_format(self, log_path: Path) -> LogFormat:
        """Auto-detect log format based on file name and content."""
        name = log_path.name.lower()
        
        if "mitmproxy" in name or "mitm" in name:
            return LogFormat.MITMPROXY
        elif "poc_execution" in name or "poc" in name:
            return LogFormat.POC_EXECUTION
        elif name.endswith('.har'):
            return LogFormat.HAR
        elif "chrome" in name and "debug" in name:
            return LogFormat.CHROME_DEBUG
        elif "console" in name:
            return LogFormat.BROWSER_CONSOLE
        else:
            # Default to mitmproxy for unknown formats
            self.logger.warning(f"Unknown log format for {log_path}, defaulting to mitmproxy")
            return LogFormat.MITMPROXY
    
    def _parse_log_sources(self, sources: List[LogSource]) -> Dict[str, Any]:
        """Parse all log sources and combine the data."""
        all_data = {
            'sources': [],
            'requests': [],
            'responses': [],
            'connections': [],
            'errors': [],
            'tls_events': [],
            'proxy_events': [],
            'browser_events': [],
            'timeline': []
        }
        
        for source in sources:
            if not source.enabled:
                continue
                
            if not source.path.exists():
                self.logger.warning(f"Log file not found: {source.path}")
                continue
            
            try:
                parser = self.parsers.get(source.format)
                if not parser:
                    self.logger.warning(f"No parser available for format: {source.format}")
                    continue
                
                self.logger.info(f"Parsing {source.path} as {source.format.value}")
                parsed_data = parser.parse(source.path)
                
                # Merge parsed data into combined dataset
                all_data['sources'].append({
                    'path': str(source.path),
                    'format': source.format.value,
                    'data': parsed_data
                })
                
                # Merge specific data types
                for key in ['requests', 'responses', 'connections', 'errors', 
                          'tls_events', 'proxy_events', 'browser_events', 'timeline']:
                    if key in parsed_data:
                        all_data[key].extend(parsed_data[key])
                
            except Exception as e:
                self.logger.error(f"Failed to parse {source.path}: {e}")
                all_data['errors'].append({
                    'source': str(source.path),
                    'error': str(e),
                    'timestamp': datetime.now()
                })
        
        self.parsed_data = all_data
        return all_data
    
    def _run_detectors(self, parsed_data: Dict[str, Any]) -> List[CriticalIssue]:
        """Run all enabled detectors on the parsed data."""
        all_issues = []
        
        for category, detector in self.detectors.items():
            try:
                self.logger.debug(f"Running {category.value} detector")
                issues = detector.detect(parsed_data)
                all_issues.extend(issues)
                self.logger.debug(f"{category.value} detector found {len(issues)} issues")
                
            except Exception as e:
                self.logger.error(f"Detector {category.value} failed: {e}")
                # Add detector failure as an issue
                error_issue = CriticalIssue(
                    id=f"DETECTOR_ERROR_{category.value.upper()}",
                    category=category,
                    severity=SeverityLevel.HIGH,
                    title=f"{category.value} Detector Failed",
                    description=f"Detector encountered an error: {str(e)}",
                    impact_score=75
                )
                all_issues.append(error_issue)
        
        # Sort by impact score (highest first)
        all_issues.sort(key=lambda x: x.impact_score, reverse=True)
        
        # Apply max issues per category limit
        limited_issues = []
        category_counts = {}
        
        for issue in all_issues:
            category_key = issue.category.value
            current_count = category_counts.get(category_key, 0)
            
            if current_count < self.config.max_issues_per_category:
                limited_issues.append(issue)
                category_counts[category_key] = current_count + 1
        
        return limited_issues
    
    def _build_network_trace(self, parsed_data: Dict[str, Any]) -> List[NetworkHop]:
        """Build comprehensive network trace from parsed data."""
        network_trace = []
        
        # Extract connection data from various sources
        connections = parsed_data.get('connections', [])
        proxy_events = parsed_data.get('proxy_events', [])
        tls_events = parsed_data.get('tls_events', [])
        
        # Build hop-by-hop trace
        hop_number = 1
        
        # Client hop
        client_hop = NetworkHop(
            hop_number=hop_number,
            actor="Client",
            incoming_ip="[local]",
            outgoing_ip="127.0.0.1:8080",
            actor_name="Browser/Application",
            risk_level=RiskLevel.SAFE,
            detection_vectors=[]
        )
        network_trace.append(client_hop)
        hop_number += 1
        
        # Local proxy hop
        proxy_hop = NetworkHop(
            hop_number=hop_number,
            actor="Local Proxy",
            incoming_ip="127.0.0.1:8080",
            outgoing_ip="unknown",
            actor_name="mitmproxy",
            risk_level=RiskLevel.MEDIUM,
            detection_vectors=["Proxy headers", "Certificate substitution"]
        )
        network_trace.append(proxy_hop)
        hop_number += 1
        
        # Add upstream proxy hops based on parsed data
        upstream_ips = set()
        for connection in connections:
            if connection.get('upstream_proxy'):
                upstream_ips.add(connection['upstream_proxy'])
        
        for upstream_ip in upstream_ips:
            upstream_hop = NetworkHop(
                hop_number=hop_number,
                actor="Upstream Proxy",
                incoming_ip=upstream_ip,
                outgoing_ip="exit_ip",
                actor_name=f"Proxy Server ({upstream_ip})",
                risk_level=RiskLevel.MEDIUM,
                detection_vectors=["Proxy via headers", "IP geolocation"]
            )
            network_trace.append(upstream_hop)
            hop_number += 1
        
        # Add TLS information where available
        for hop in network_trace:
            matching_tls = None
            for tls_event in tls_events:
                if (tls_event.get('server_ip') == hop.outgoing_ip or
                    tls_event.get('client_ip') == hop.incoming_ip):
                    matching_tls = tls_event
                    break
            
            if matching_tls:
                hop.tls_info = TLSInfo(
                    version=matching_tls.get('tls_version'),
                    cipher_suite=matching_tls.get('cipher_suite'),
                    handshake_success=matching_tls.get('success', True)
                )
        
        return network_trace
    
    def _calculate_performance_metrics(self, parsed_data: Dict[str, Any]) -> PerformanceMetrics:
        """Calculate performance metrics from parsed data."""
        requests = parsed_data.get('requests', [])
        responses = parsed_data.get('responses', [])
        
        total_requests = len(requests)
        successful_responses = len([r for r in responses if 200 <= r.get('status_code', 0) < 300])
        failed_responses = len(responses) - successful_responses
        
        response_times = [r.get('response_time', 0) for r in responses if r.get('response_time')]
        
        return PerformanceMetrics(
            total_requests=total_requests,
            successful_requests=successful_responses,
            failed_requests=failed_responses,
            average_response_time_ms=sum(response_times) / len(response_times) if response_times else 0,
            max_response_time_ms=max(response_times) if response_times else 0,
            min_response_time_ms=min(response_times) if response_times else 0,
            success_rate_percent=(successful_responses / total_requests * 100) if total_requests > 0 else 0
        )
    
    def _generate_summary(
        self,
        issues: List[CriticalIssue],
        network_trace: List[NetworkHop],
        performance: PerformanceMetrics
    ) -> AnalysisSummary:
        """Generate high-level analysis summary."""
        critical_count = len([i for i in issues if i.severity == SeverityLevel.CRITICAL])
        high_count = len([i for i in issues if i.severity == SeverityLevel.HIGH])
        medium_count = len([i for i in issues if i.severity == SeverityLevel.MEDIUM])
        
        # Calculate overall score
        if critical_count > 0:
            overall_score = max(0, 50 - (critical_count * 20))
        elif high_count > 0:
            overall_score = max(50, 75 - (high_count * 10))
        else:
            overall_score = max(75, 100 - (medium_count * 5))
        
        # Determine status
        if overall_score >= 80:
            status = "SUCCESS"
        elif overall_score >= 60:
            status = "PARTIAL_SUCCESS"
        else:
            status = "FAILED"
        
        # Check functional indicators
        proxy_functional = performance.success_rate_percent > 80
        oauth_success = any('oauth' in str(issue.description).lower() and 
                           issue.severity != SeverityLevel.CRITICAL for issue in issues)
        antibot_bypass = not any('bot' in str(issue.description).lower() and 
                                issue.severity == SeverityLevel.CRITICAL for issue in issues)
        geo_masking = not any('geo' in str(issue.description).lower() and 
                             issue.severity == SeverityLevel.CRITICAL for issue in issues)
        
        return AnalysisSummary(
            status=status,
            overall_score=overall_score,
            critical_issues_count=critical_count,
            high_issues_count=high_count,
            medium_issues_count=medium_count,
            total_issues_count=len(issues),
            proxy_chain_functional=proxy_functional,
            oauth_success=oauth_success,
            antibot_bypass_success=antibot_bypass,
            geographic_masking_active=geo_masking,
            timestamp=datetime.now()
        )
    
    def _generate_timeline(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate session timeline (optional feature)."""
        timeline_events = parsed_data.get('timeline', [])
        return sorted(timeline_events, key=lambda x: x.get('timestamp', ''))
    
    def _compare_fingerprints(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Compare browser fingerprints (optional feature)."""
        # Placeholder for fingerprint comparison logic
        return {
            'fingerprint_detected': False,
            'comparison_result': 'Not implemented',
            'recommendations': []
        }
    
    def _generate_remediation(self, issues: List[CriticalIssue]) -> List[Dict[str, str]]:
        """Generate auto-remediation suggestions."""
        suggestions = []
        
        for issue in issues[:5]:  # Top 5 issues
            if issue.recommendation or issue.code_fix:
                suggestion = {
                    'issue_id': issue.id,
                    'title': issue.title,
                    'recommendation': issue.recommendation or 'No specific recommendation available',
                    'code_fix': issue.code_fix or '',
                    'priority': issue.severity.value
                }
                suggestions.append(suggestion)
        
        return suggestions
    
    def export_results(
        self,
        results: AnalysisResult,
        output_path: Union[str, Path],
        format_type: str = "json"
    ) -> None:
        """Export analysis results to file."""
        output_path = Path(output_path)
        
        if format_type == "json":
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results.to_dict(), f, indent=2, default=str)
        elif format_type == "text":
            report_text = self.report_generator.generate_text_report(results)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_text)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
        
        self.logger.info(f"Results exported to {output_path}")
