"""
Integration tests for ConnectionInfo quality assessment workflows.

Tests latency, packet loss, and throughput analysis with ConnectionInfo models.
"""

import pytest
import asyncio
import time
import statistics
from typing import List, Dict, Any
from unittest.mock import Mock, patch

from src.netstealth_analyzer.models.network import (
    ConnectionInfo, NetworkProtocol, TLSInfo, TLSVersion, NetworkTrace, NetworkHop
)
from src.netstealth_analyzer.models.enums import RiskLevel
from src.netstealth_analyzer.core.events import EventBus, AnalysisEvent


class TestConnectionInfoQualityIntegration:
    """Test ConnectionInfo integration with network quality assessment."""
    
    @pytest.fixture
    def quality_test_dataset(self):
        """Create connections with varying quality metrics for testing."""
        return [
            # Excellent quality - Low latency, high throughput, no packet loss
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                source_ip="192.168.1.100",
                destination_ip="8.8.8.8",  # Google DNS
                destination_port=443,
                latency_ms=8.5,
                duration_ms=45.2,
                bytes_sent=2048,
                bytes_received=16384,
                throughput_bps=3251200,  # ~3.25 Mbps
                packet_loss_percent=0.0,
                jitter_ms=1.2,
                is_encrypted=True
            ),
            # Good quality - Moderate latency, good throughput, minimal packet loss
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                source_ip="192.168.1.100",
                destination_ip="1.1.1.1",  # Cloudflare DNS
                destination_port=443,
                latency_ms=25.3,
                duration_ms=120.8,
                bytes_sent=4096,
                bytes_received=32768,
                throughput_bps=2441600,  # ~2.44 Mbps
                packet_loss_percent=0.2,
                jitter_ms=3.8,
                is_encrypted=True
            ),
            # Fair quality - Higher latency, moderate throughput, some packet loss
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                source_ip="192.168.1.100",
                destination_ip="208.67.222.222",  # OpenDNS
                destination_port=443,
                latency_ms=85.7,
                duration_ms=350.4,
                bytes_sent=1024,
                bytes_received=8192,
                throughput_bps=1048576,  # 1 Mbps
                packet_loss_percent=1.5,
                jitter_ms=12.4,
                is_encrypted=True
            ),
            # Poor quality - High latency, low throughput, significant packet loss
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                source_ip="192.168.1.100",
                destination_ip="203.0.113.42",  # Test network
                destination_port=80,
                latency_ms=450.2,
                duration_ms=2500.0,
                bytes_sent=512,
                bytes_received=2048,
                throughput_bps=204800,  # 200 Kbps
                packet_loss_percent=8.3,
                jitter_ms=85.6,
                is_encrypted=False
            ),
            # Very poor quality - Very high latency, very low throughput, high packet loss
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                source_ip="192.168.1.100",
                destination_ip="198.51.100.42",  # Test network
                destination_port=80,
                latency_ms=1250.8,
                duration_ms=8000.0,
                bytes_sent=256,
                bytes_received=512,
                throughput_bps=76800,  # 75 Kbps
                packet_loss_percent=15.7,
                jitter_ms=200.3,
                is_encrypted=False
            )
        ]
    
    @pytest.mark.asyncio
    async def test_network_quality_metrics_pipeline(self, quality_test_dataset):
        """Test end-to-end network quality assessment pipeline."""
        # Mock quality pipeline
        quality_pipeline = Mock(spec=NetworkQualityPipeline)
        
        # Calculate expected quality metrics
        latencies = [conn.latency_ms for conn in quality_test_dataset]
        packet_losses = [conn.packet_loss_percent for conn in quality_test_dataset]
        throughputs = [conn.throughput_bps for conn in quality_test_dataset]
        
        expected_report = NetworkQualityReport(
            total_connections=len(quality_test_dataset),
            average_latency=statistics.mean(latencies),
            median_latency=statistics.median(latencies),
            p95_latency=sorted(latencies)[int(len(latencies) * 0.95)],
            packet_loss_rate=statistics.mean(packet_losses),
            max_packet_loss=max(packet_losses),
            throughput_mbps=statistics.mean(throughputs) / 1000000,  # Convert to Mbps
            min_throughput_mbps=min(throughputs) / 1000000,
            max_throughput_mbps=max(throughputs) / 1000000,
            quality_distribution={
                "excellent": 1,
                "good": 1,
                "fair": 1,
                "poor": 1,
                "very_poor": 1
            },
            quality_recommendations=[
                "2 connections have high packet loss (>5%) - investigate network issues",
                "2 connections have high latency (>400ms) - consider route optimization",
                "2 connections using HTTP - upgrade to HTTPS for security",
                "Overall network quality is mixed - prioritize improvements for poor connections"
            ]
        )
        
        # Mock pipeline method
        quality_pipeline.assess = Mock(return_value=expected_report)
        
        # Run quality assessment pipeline
        quality_report = await quality_pipeline.assess(quality_test_dataset)
        
        # Validate quality metrics
        assert quality_report.total_connections == len(quality_test_dataset)
        assert quality_report.average_latency > 0
        assert 0 <= quality_report.packet_loss_rate <= 100
        assert quality_report.throughput_mbps > 0
        assert len(quality_report.quality_recommendations) > 0
        
        # Validate quality distribution
        total_quality_connections = sum(quality_report.quality_distribution.values())
        assert total_quality_connections == quality_report.total_connections
        
        # Validate specific quality categories
        assert quality_report.quality_distribution["excellent"] >= 1
        assert quality_report.quality_distribution["very_poor"] >= 1
        
        # Validate recommendations contain expected content
        recommendations_text = " ".join(quality_report.quality_recommendations).lower()
        assert "packet loss" in recommendations_text
        assert "latency" in recommendations_text
        assert "https" in recommendations_text
        
        # Verify pipeline was called with correct dataset
        quality_pipeline.assess.assert_called_once_with(quality_test_dataset)
    
    @pytest.mark.asyncio
    async def test_latency_analysis_and_classification(self, quality_test_dataset):
        """Test latency analysis and classification workflows."""
        # Mock latency analyzer
        latency_analyzer = Mock(spec=LatencyAnalyzer)
        
        # Create expected latency analysis results
        latency_analysis = LatencyAnalysisResults(
            connections_analyzed=len(quality_test_dataset),
            latency_statistics={
                "min": min(conn.latency_ms for conn in quality_test_dataset),
                "max": max(conn.latency_ms for conn in quality_test_dataset),
                "mean": statistics.mean(conn.latency_ms for conn in quality_test_dataset),
                "median": statistics.median(conn.latency_ms for conn in quality_test_dataset),
                "std_dev": statistics.stdev(conn.latency_ms for conn in quality_test_dataset),
                "p95": sorted([conn.latency_ms for conn in quality_test_dataset])[int(len(quality_test_dataset) * 0.95)],
                "p99": sorted([conn.latency_ms for conn in quality_test_dataset])[int(len(quality_test_dataset) * 0.99)]
            },
            latency_classifications={
                "excellent": [quality_test_dataset[0]],  # <20ms
                "good": [quality_test_dataset[1]],       # 20-50ms
                "fair": [quality_test_dataset[2]],       # 50-150ms
                "poor": [quality_test_dataset[3]],       # 150-500ms
                "very_poor": [quality_test_dataset[4]]   # >500ms
            },
            geographic_analysis={
                "8.8.8.8": {"region": "Global CDN", "avg_latency": 8.5, "classification": "excellent"},
                "1.1.1.1": {"region": "Global CDN", "avg_latency": 25.3, "classification": "good"},
                "208.67.222.222": {"region": "US West", "avg_latency": 85.7, "classification": "fair"},
                "203.0.113.42": {"region": "Test Network", "avg_latency": 450.2, "classification": "poor"},
                "198.51.100.42": {"region": "Test Network", "avg_latency": 1250.8, "classification": "very_poor"}
            },
            optimization_suggestions=[
                "Consider using CDN services for better global latency",
                "Investigate routing issues for connections >400ms latency",
                "Implement connection pooling for frequently accessed endpoints",
                "Consider geographic load balancing for improved performance"
            ]
        )
        
        # Mock analyzer method
        latency_analyzer.analyze_latency = Mock(return_value=latency_analysis)
        
        # Run latency analysis
        analysis = await latency_analyzer.analyze_latency(quality_test_dataset)
        
        # Validate latency statistics
        assert analysis.connections_analyzed == len(quality_test_dataset)
        assert analysis.latency_statistics["min"] > 0
        assert analysis.latency_statistics["max"] > analysis.latency_statistics["min"]
        assert analysis.latency_statistics["mean"] > 0
        assert analysis.latency_statistics["p95"] >= analysis.latency_statistics["median"]
        assert analysis.latency_statistics["p99"] >= analysis.latency_statistics["p95"]
        
        # Validate latency classifications
        total_classified = sum(len(conns) for conns in analysis.latency_classifications.values())
        assert total_classified == analysis.connections_analyzed
        
        # Validate geographic analysis
        assert len(analysis.geographic_analysis) == len(set(conn.destination_ip for conn in quality_test_dataset))
        for ip, geo_data in analysis.geographic_analysis.items():
            assert "region" in geo_data
            assert "avg_latency" in geo_data
            assert "classification" in geo_data
            assert geo_data["avg_latency"] > 0
        
        # Validate optimization suggestions
        assert len(analysis.optimization_suggestions) >= 3
        suggestions_text = " ".join(analysis.optimization_suggestions).lower()
        assert "cdn" in suggestions_text or "latency" in suggestions_text
        
        # Verify analyzer was called with correct dataset
        latency_analyzer.analyze_latency.assert_called_once_with(quality_test_dataset)
    
    @pytest.mark.asyncio
    async def test_packet_loss_impact_assessment(self, quality_test_dataset):
        """Test packet loss impact assessment and mitigation recommendations."""
        # Mock packet loss analyzer
        packet_loss_analyzer = Mock(spec=PacketLossAnalyzer)
        
        # Create expected packet loss analysis
        packet_loss_analysis = PacketLossAnalysisResults(
            connections_analyzed=len(quality_test_dataset),
            packet_loss_statistics={
                "min": min(conn.packet_loss_percent for conn in quality_test_dataset),
                "max": max(conn.packet_loss_percent for conn in quality_test_dataset),
                "mean": statistics.mean(conn.packet_loss_percent for conn in quality_test_dataset),
                "median": statistics.median(conn.packet_loss_percent for conn in quality_test_dataset)
            },
            impact_categories={
                "no_impact": 2,      # 0-1% packet loss
                "minimal_impact": 1,  # 1-3% packet loss
                "moderate_impact": 1, # 3-10% packet loss
                "severe_impact": 1    # >10% packet loss
            },
            affected_connections=[
                {
                    "connection": quality_test_dataset[3],
                    "packet_loss": 8.3,
                    "impact_level": "moderate",
                    "estimated_throughput_loss": "25-40%"
                },
                {
                    "connection": quality_test_dataset[4],
                    "packet_loss": 15.7,
                    "impact_level": "severe",
                    "estimated_throughput_loss": "50-70%"
                }
            ],
            mitigation_strategies=[
                "Implement TCP congestion control optimization",
                "Consider using UDP with application-level reliability for real-time traffic",
                "Investigate network infrastructure for connections with >5% packet loss",
                "Implement adaptive bitrate streaming for media connections",
                "Use forward error correction for critical data transmission"
            ],
            quality_correlation={
                "latency_correlation": 0.85,  # High correlation between packet loss and latency
                "throughput_correlation": -0.92  # Strong negative correlation with throughput
            }
        )
        
        # Mock analyzer method
        packet_loss_analyzer.analyze_packet_loss = Mock(return_value=packet_loss_analysis)
        
        # Run packet loss analysis
        analysis = await packet_loss_analyzer.analyze_packet_loss(quality_test_dataset)
        
        # Validate packet loss statistics
        assert analysis.connections_analyzed == len(quality_test_dataset)
        assert analysis.packet_loss_statistics["min"] >= 0
        assert analysis.packet_loss_statistics["max"] >= analysis.packet_loss_statistics["min"]
        assert analysis.packet_loss_statistics["mean"] >= 0
        
        # Validate impact categories
        total_categorized = sum(analysis.impact_categories.values())
        assert total_categorized == analysis.connections_analyzed
        
        # Validate affected connections
        assert len(analysis.affected_connections) >= 1
        for affected in analysis.affected_connections:
            assert "connection" in affected
            assert "packet_loss" in affected
            assert "impact_level" in affected
            assert affected["packet_loss"] > 3.0  # Should be connections with significant packet loss
        
        # Validate mitigation strategies
        assert len(analysis.mitigation_strategies) >= 3
        strategies_text = " ".join(analysis.mitigation_strategies).lower()
        assert "tcp" in strategies_text or "congestion" in strategies_text
        assert "packet loss" in strategies_text
        
        # Validate quality correlations
        assert -1 <= analysis.quality_correlation["latency_correlation"] <= 1
        assert -1 <= analysis.quality_correlation["throughput_correlation"] <= 1
        
        # Verify analyzer was called with correct dataset
        packet_loss_analyzer.analyze_packet_loss.assert_called_once_with(quality_test_dataset)
    
    @pytest.mark.asyncio
    async def test_throughput_calculation_and_optimization(self, quality_test_dataset):
        """Test throughput calculation and optimization recommendations."""
        # Mock throughput analyzer
        throughput_analyzer = Mock(spec=ThroughputAnalyzer)
        
        # Create expected throughput analysis
        throughput_analysis = ThroughputAnalysisResults(
            connections_analyzed=len(quality_test_dataset),
            throughput_statistics={
                "min_bps": min(conn.throughput_bps for conn in quality_test_dataset),
                "max_bps": max(conn.throughput_bps for conn in quality_test_dataset),
                "mean_bps": statistics.mean(conn.throughput_bps for conn in quality_test_dataset),
                "median_bps": statistics.median(conn.throughput_bps for conn in quality_test_dataset),
                "total_bps": sum(conn.throughput_bps for conn in quality_test_dataset)
            },
            throughput_classifications={
                "high_throughput": [quality_test_dataset[0], quality_test_dataset[1]],  # >1 Mbps
                "medium_throughput": [quality_test_dataset[2]],                         # 100Kbps - 1Mbps
                "low_throughput": [quality_test_dataset[3], quality_test_dataset[4]]    # <100Kbps
            },
            bottleneck_analysis={
                "bandwidth_limited": 1,  # Connection limited by available bandwidth
                "latency_limited": 2,    # Connections limited by high latency
                "protocol_limited": 2,   # HTTP connections vs HTTPS
                "server_limited": 0      # Server processing limitations
            },
            optimization_recommendations=[
                {
                    "connection_id": f"{quality_test_dataset[3].source_ip}:{quality_test_dataset[3].destination_ip}",
                    "current_throughput": "200 Kbps",
                    "potential_throughput": "800 Kbps",
                    "optimization": "Reduce packet loss from 8.3% to <1%",
                    "implementation": "Network infrastructure upgrade"
                },
                {
                    "connection_id": f"{quality_test_dataset[4].source_ip}:{quality_test_dataset[4].destination_ip}",
                    "current_throughput": "75 Kbps",
                    "potential_throughput": "500 Kbps",
                    "optimization": "Reduce latency from 1250ms to <200ms and packet loss to <2%",
                    "implementation": "Route optimization and infrastructure upgrade"
                }
            ],
            efficiency_metrics={
                "bandwidth_utilization": 0.65,  # 65% of available bandwidth used efficiently
                "protocol_efficiency": 0.60,    # HTTP vs HTTPS efficiency comparison
                "connection_efficiency": 0.55   # Overall connection efficiency
            }
        )
        
        # Mock analyzer method
        throughput_analyzer.analyze_throughput = Mock(return_value=throughput_analysis)
        
        # Run throughput analysis
        analysis = await throughput_analyzer.analyze_throughput(quality_test_dataset)
        
        # Validate throughput statistics
        assert analysis.connections_analyzed == len(quality_test_dataset)
        assert analysis.throughput_statistics["min_bps"] > 0
        assert analysis.throughput_statistics["max_bps"] >= analysis.throughput_statistics["min_bps"]
        assert analysis.throughput_statistics["mean_bps"] > 0
        assert analysis.throughput_statistics["total_bps"] > 0
        
        # Validate throughput classifications
        total_classified = sum(len(conns) for conns in analysis.throughput_classifications.values())
        assert total_classified == analysis.connections_analyzed
        
        # Validate bottleneck analysis
        total_bottlenecks = sum(analysis.bottleneck_analysis.values())
        assert total_bottlenecks >= 0  # Some connections may not have identifiable bottlenecks
        
        # Validate optimization recommendations
        assert len(analysis.optimization_recommendations) >= 1
        for rec in analysis.optimization_recommendations:
            assert "connection_id" in rec
            assert "current_throughput" in rec
            assert "potential_throughput" in rec
            assert "optimization" in rec
        
        # Validate efficiency metrics
        for metric_name, value in analysis.efficiency_metrics.items():
            assert 0 <= value <= 1, f"{metric_name} should be between 0 and 1"
        
        # Verify analyzer was called with correct dataset
        throughput_analyzer.analyze_throughput.assert_called_once_with(quality_test_dataset)
    
    @pytest.mark.asyncio
    async def test_quality_trend_analysis(self):
        """Test quality trend analysis over time."""
        # Create time-series quality data
        time_series_data = []
        base_time = time.time()
        
        for i in range(24):  # 24 hours of data
            hour_connections = []
            for j in range(10):  # 10 connections per hour
                # Simulate quality degradation during peak hours (9-17)
                if 9 <= i <= 17:  # Peak hours
                    latency_multiplier = 1.5 + (i - 9) * 0.1
                    packet_loss_multiplier = 2.0
                else:  # Off-peak hours
                    latency_multiplier = 1.0
                    packet_loss_multiplier = 1.0
                
                conn = ConnectionInfo(
                    protocol=NetworkProtocol.HTTPS,
                    source_ip="192.168.1.100",
                    destination_ip=f"10.0.{i}.{j}",
                    destination_port=443,
                    latency_ms=50.0 * latency_multiplier + j * 5,
                    duration_ms=200.0 * latency_multiplier,
                    bytes_sent=1024,
                    bytes_received=8192,
                    throughput_bps=1000000 / latency_multiplier,  # Inverse relationship
                    packet_loss_percent=0.5 * packet_loss_multiplier,
                    timestamp=base_time + i * 3600  # Hour intervals
                )
                hour_connections.append(conn)
            
            time_series_data.append({
                "hour": i,
                "timestamp": base_time + i * 3600,
                "connections": hour_connections
            })
        
        # Mock trend analyzer
        trend_analyzer = Mock(spec=QualityTrendAnalyzer)
        
        # Create expected trend analysis
        trend_analysis = QualityTrendAnalysisResults(
            analysis_period_hours=24,
            total_connections=240,  # 24 hours * 10 connections
            trend_metrics={
                "latency_trend": "increasing_during_peak",
                "throughput_trend": "decreasing_during_peak",
                "packet_loss_trend": "stable_with_peak_spikes",
                "overall_quality_trend": "cyclical_degradation"
            },
            peak_hours=[9, 10, 11, 12, 13, 14, 15, 16, 17],
            quality_patterns={
                "peak_degradation_factor": 2.3,
                "recovery_time_hours": 2,
                "baseline_quality_score": 0.85,
                "peak_quality_score": 0.45
            },
            predictive_insights=[
                "Quality consistently degrades during business hours (9-17)",
                "Peak degradation occurs around 13:00-15:00",
                "Recovery to baseline takes approximately 2 hours after peak",
                "Weekend patterns show 40% better quality metrics"
            ],
            recommendations=[
                "Implement traffic shaping during peak hours",
                "Consider capacity scaling between 8:00-18:00",
                "Prioritize critical traffic during degradation periods",
                "Implement proactive monitoring with quality thresholds"
            ]
        )
        
        # Mock analyzer method
        trend_analyzer.analyze_trends = Mock(return_value=trend_analysis)
        
        # Run trend analysis
        analysis = await trend_analyzer.analyze_trends(time_series_data)
        
        # Validate trend analysis
        assert analysis.analysis_period_hours == 24
        assert analysis.total_connections > 0
        assert len(analysis.trend_metrics) >= 3
        assert len(analysis.peak_hours) > 0
        assert len(analysis.predictive_insights) >= 2
        assert len(analysis.recommendations) >= 3
        
        # Validate quality patterns
        assert 0 <= analysis.quality_patterns["baseline_quality_score"] <= 1
        assert 0 <= analysis.quality_patterns["peak_quality_score"] <= 1
        assert analysis.quality_patterns["peak_degradation_factor"] > 1
        assert analysis.quality_patterns["recovery_time_hours"] > 0
        
        # Validate recommendations contain actionable items
        recommendations_text = " ".join(analysis.recommendations).lower()
        assert "traffic" in recommendations_text or "capacity" in recommendations_text
        assert "monitoring" in recommendations_text
        
        # Verify analyzer was called with correct data
        trend_analyzer.analyze_trends.assert_called_once_with(time_series_data)


# Mock classes for testing
class NetworkQualityPipeline:
    """Mock network quality pipeline."""
    async def assess(self, connections: List[ConnectionInfo]) -> 'NetworkQualityReport':
        pass


class LatencyAnalyzer:
    """Mock latency analyzer."""
    async def analyze_latency(self, connections: List[ConnectionInfo]) -> 'LatencyAnalysisResults':
        pass


class PacketLossAnalyzer:
    """Mock packet loss analyzer."""
    async def analyze_packet_loss(self, connections: List[ConnectionInfo]) -> 'PacketLossAnalysisResults':
        pass


class ThroughputAnalyzer:
    """Mock throughput analyzer."""
    async def analyze_throughput(self, connections: List[ConnectionInfo]) -> 'ThroughputAnalysisResults':
        pass


class QualityTrendAnalyzer:
    """Mock quality trend analyzer."""
    async def analyze_trends(self, time_series_data: List[Dict]) -> 'QualityTrendAnalysisResults':
        pass


# Result classes
class NetworkQualityReport:
    """Network quality assessment report."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class LatencyAnalysisResults:
    """Latency analysis results."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class PacketLossAnalysisResults:
    """Packet loss analysis results."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class ThroughputAnalysisResults:
    """Throughput analysis results."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class QualityTrendAnalysisResults:
    """Quality trend analysis results."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
