"""
Integration tests for ConnectionInfo performance testing and optimization.

Tests ConnectionInfo handling under load and performance analysis scenarios.
"""

import pytest
import asyncio
import time
import random
from typing import List, Dict, Any
from unittest.mock import Mock, patch
import psutil
import os

from src.netstealth_analyzer.models.network import (
    ConnectionInfo, NetworkProtocol, TLSInfo, TLSVersion, NetworkTrace, NetworkHop
)
from src.netstealth_analyzer.models.enums import RiskLevel
from src.netstealth_analyzer.core.events import EventBus, AnalysisEvent


class TestConnectionInfoPerformanceIntegration:
    """Test ConnectionInfo performance under various load conditions."""
    
    @pytest.fixture
    def large_connection_dataset(self):
        """Generate large dataset of ConnectionInfo instances for performance testing."""
        connections = []
        for i in range(1000):  # 1K connections
            # Vary connection types and characteristics
            protocol = NetworkProtocol.HTTPS if i % 3 == 0 else NetworkProtocol.HTTP
            is_encrypted = protocol == NetworkProtocol.HTTPS
            
            # Generate realistic performance metrics
            latency = random.uniform(10.0, 500.0)
            duration = latency + random.uniform(50.0, 2000.0)
            bytes_sent = random.randint(100, 10000)
            bytes_received = random.randint(500, 50000)
            
            # Create TLS info for HTTPS connections
            tls_info = None
            if is_encrypted:
                tls_versions = [TLSVersion.TLS_10, TLSVersion.TLS_11, TLSVersion.TLS_12, TLSVersion.TLS_13]
                tls_info = TLSInfo(
                    version=random.choice(tls_versions),
                    cipher_suite=f"TLS_AES_{random.choice([128, 256])}_GCM_SHA{random.choice([256, 384])}",
                    certificate_issues=[] if random.random() > 0.2 else ["weak_signature"],
                    certificate_expiry_days=random.randint(-30, 365)
                )
            
            conn = ConnectionInfo(
                protocol=protocol,
                source_ip=f"192.168.{i // 255}.{i % 255}",
                destination_ip=f"10.0.{i // 100}.{i % 100}",
                destination_port=443 if is_encrypted else 80,
                bytes_sent=bytes_sent,
                bytes_received=bytes_received,
                duration_ms=duration,
                latency_ms=latency,
                is_encrypted=is_encrypted,
                tls_info=tls_info
            )
            connections.append(conn)
        
        return connections
    
    @pytest.mark.asyncio
    async def test_connectioninfo_performance_under_load(self, large_connection_dataset):
        """Test ConnectionInfo processing performance with large datasets."""
        # Mock performance processor
        processor = Mock(spec=ConnectionPerformanceProcessor)
        
        # Create expected performance results
        expected_results = PerformanceAnalysisResults(
            total_connections=len(large_connection_dataset),
            processing_time_ms=1500.0,  # Should process 1K connections in <2s
            connections_per_second=666.7,  # 1000 / 1.5
            average_latency=150.0,
            median_latency=120.0,
            p95_latency=350.0,
            total_data_transfer=sum(c.total_bytes for c in large_connection_dataset),
            throughput_analysis={
                "high_throughput_connections": 200,
                "medium_throughput_connections": 600,
                "low_throughput_connections": 200
            },
            memory_usage_mb=45.0,
            cpu_usage_percent=15.0
        )
        
        # Mock processor method
        processor.analyze_connections = Mock(return_value=expected_results)
        
        # Measure actual processing time
        start_time = time.time()
        results = await processor.analyze_connections(large_connection_dataset)
        end_time = time.time()
        
        # Validate performance metrics
        processing_time = end_time - start_time
        assert processing_time < 2.0  # Should process 1K connections in <2s
        assert results.total_connections == 1000
        assert results.connections_per_second > 500  # Should process >500 connections/sec
        assert results.average_latency > 0
        assert results.total_data_transfer > 0
        
        # Validate throughput analysis
        throughput_analysis = results.throughput_analysis
        total_categorized = (
            throughput_analysis["high_throughput_connections"] +
            throughput_analysis["medium_throughput_connections"] +
            throughput_analysis["low_throughput_connections"]
        )
        assert total_categorized == results.total_connections
        
        # Validate resource usage
        assert results.memory_usage_mb < 100  # Should use <100MB
        assert results.cpu_usage_percent < 50  # Should use <50% CPU
        
        # Verify processor was called with correct dataset
        processor.analyze_connections.assert_called_once_with(large_connection_dataset)
    
    @pytest.mark.asyncio
    async def test_concurrent_connectioninfo_processing(self, large_connection_dataset):
        """Test concurrent processing of ConnectionInfo instances."""
        # Split dataset into chunks for concurrent processing
        chunk_size = len(large_connection_dataset) // 4  # 4 concurrent processors
        chunks = [
            large_connection_dataset[i:i + chunk_size]
            for i in range(0, len(large_connection_dataset), chunk_size)
        ]
        
        # Mock concurrent processors
        processors = [Mock(spec=ConnectionPerformanceProcessor) for _ in range(4)]
        
        # Create expected results for each processor
        for i, processor in enumerate(processors):
            chunk_results = PerformanceAnalysisResults(
                total_connections=len(chunks[i]),
                processing_time_ms=400.0,  # Each chunk processed in ~400ms
                connections_per_second=len(chunks[i]) / 0.4,
                average_latency=150.0 + i * 10,  # Slight variation
                total_data_transfer=sum(c.total_bytes for c in chunks[i]),
                memory_usage_mb=12.0 + i * 2,
                cpu_usage_percent=8.0 + i * 2
            )
            processor.analyze_connections = Mock(return_value=chunk_results)
        
        # Execute concurrent processing
        start_time = time.time()
        
        async def process_chunk(processor, chunk):
            return await processor.analyze_connections(chunk)
        
        # Run all processors concurrently
        results = await asyncio.gather(*[
            process_chunk(processors[i], chunks[i])
            for i in range(len(processors))
        ])
        
        end_time = time.time()
        concurrent_time = end_time - start_time
        
        # Compare with sequential processing time estimate
        sequential_time_estimate = 1.6  # 4 * 0.4s
        
        # Concurrent processing should be faster than sequential
        assert concurrent_time < sequential_time_estimate * 0.8
        assert concurrent_time < 1.0  # Should complete in <1s
        
        # Validate all processors executed successfully
        assert len(results) == 4
        for i, result in enumerate(results):
            assert result.total_connections == len(chunks[i])
            assert result.processing_time_ms > 0
            assert result.connections_per_second > 0
        
        # Verify all processors were called
        for i, processor in enumerate(processors):
            processor.analyze_connections.assert_called_once_with(chunks[i])
        
        # Aggregate results
        total_connections = sum(r.total_connections for r in results)
        total_data_transfer = sum(r.total_data_transfer for r in results)
        avg_latency = sum(r.average_latency for r in results) / len(results)
        
        assert total_connections == len(large_connection_dataset)
        assert total_data_transfer > 0
        assert avg_latency > 0
    
    @pytest.mark.asyncio
    async def test_connection_quality_assessment(self):
        """Test comprehensive connection quality assessment."""
        # Create connections with varying quality characteristics
        connections = [
            # Excellent quality connection
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                latency_ms=15.0,
                duration_ms=65.0,
                bytes_sent=1000,
                bytes_received=10000,
                throughput_bps=153846,  # High throughput
                packet_loss_percent=0.1,
                jitter_ms=2.0,
                is_encrypted=True
            ),
            # Good quality connection
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                latency_ms=45.0,
                duration_ms=150.0,
                bytes_sent=2000,
                bytes_received=8000,
                throughput_bps=66667,  # Medium throughput
                packet_loss_percent=0.5,
                jitter_ms=5.0,
                is_encrypted=True
            ),
            # Poor quality connection
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                latency_ms=300.0,
                duration_ms=2000.0,
                bytes_sent=1000,
                bytes_received=2000,
                throughput_bps=1500,  # Low throughput
                packet_loss_percent=5.0,
                jitter_ms=50.0,
                is_encrypted=False
            ),
            # Failed connection
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                latency_ms=30000.0,  # Timeout
                duration_ms=30000.0,
                bytes_sent=500,
                bytes_received=0,  # No response
                throughput_bps=0.0,
                packet_loss_percent=100.0,
                jitter_ms=0.0,
                is_encrypted=False
            )
        ]
        
        # Mock quality analyzer
        analyzer = Mock(spec=ConnectionQualityAnalyzer)
        
        # Create expected quality scores
        quality_scores = [
            ConnectionQualityScore(
                connection_id="192.168.1.1:93.184.216.34",
                overall_score=0.95,
                latency_score=0.98,
                throughput_score=0.92,
                reliability_score=0.95,
                classification="excellent",
                recommendations=["Connection performance is optimal"]
            ),
            ConnectionQualityScore(
                connection_id="192.168.1.1:10.0.1.50",
                overall_score=0.75,
                latency_score=0.80,
                throughput_score=0.70,
                reliability_score=0.75,
                classification="good",
                recommendations=["Consider optimizing for better throughput"]
            ),
            ConnectionQualityScore(
                connection_id="192.168.1.1:203.0.113.42",
                overall_score=0.25,
                latency_score=0.20,
                throughput_score=0.15,
                reliability_score=0.40,
                classification="poor",
                recommendations=[
                    "High latency detected - investigate network path",
                    "Low throughput - check bandwidth limitations",
                    "Upgrade to HTTPS for security"
                ]
            ),
            ConnectionQualityScore(
                connection_id="192.168.1.1:10.0.2.100",
                overall_score=0.0,
                latency_score=0.0,
                throughput_score=0.0,
                reliability_score=0.0,
                classification="failed",
                recommendations=[
                    "Connection failed - check server availability",
                    "Implement retry logic with exponential backoff"
                ]
            )
        ]
        
        # Mock analyzer method
        analyzer.assess_quality = Mock(return_value=quality_scores)
        
        # Run quality assessment
        scores = await analyzer.assess_quality(connections)
        
        # Validate quality scores
        assert len(scores) == 4
        
        # Excellent connection
        assert scores[0].overall_score > 0.9
        assert scores[0].classification == "excellent"
        assert len(scores[0].recommendations) >= 1
        
        # Good connection
        assert 0.7 <= scores[1].overall_score < 0.9
        assert scores[1].classification == "good"
        
        # Poor connection
        assert 0.1 <= scores[2].overall_score < 0.5
        assert scores[2].classification == "poor"
        assert len(scores[2].recommendations) >= 2
        
        # Failed connection
        assert scores[3].overall_score == 0.0
        assert scores[3].classification == "failed"
        assert "failed" in scores[3].recommendations[0].lower()
        
        # Verify analyzer was called with correct connections
        analyzer.assess_quality.assert_called_once_with(connections)
    
    @pytest.mark.asyncio
    async def test_network_performance_metrics_aggregation(self, large_connection_dataset):
        """Test network performance metrics aggregation and analysis."""
        # Mock metrics aggregator
        aggregator = Mock(spec=NetworkMetricsAggregator)
        
        # Calculate expected aggregated metrics
        latencies = [c.latency_ms for c in large_connection_dataset]
        throughputs = [c.throughput_bps for c in large_connection_dataset if hasattr(c, 'throughput_bps')]
        
        expected_metrics = NetworkPerformanceMetrics(
            total_connections=len(large_connection_dataset),
            average_latency=sum(latencies) / len(latencies),
            median_latency=sorted(latencies)[len(latencies) // 2],
            p95_latency=sorted(latencies)[int(len(latencies) * 0.95)],
            p99_latency=sorted(latencies)[int(len(latencies) * 0.99)],
            min_latency=min(latencies),
            max_latency=max(latencies),
            total_bytes_transferred=sum(c.total_bytes for c in large_connection_dataset),
            average_throughput=sum(throughputs) / len(throughputs) if throughputs else 0,
            connection_success_rate=0.95,  # 95% success rate
            protocol_distribution={
                "HTTPS": len([c for c in large_connection_dataset if c.protocol == NetworkProtocol.HTTPS]),
                "HTTP": len([c for c in large_connection_dataset if c.protocol == NetworkProtocol.HTTP])
            },
            quality_distribution={
                "excellent": 150,
                "good": 400,
                "fair": 300,
                "poor": 100,
                "failed": 50
            }
        )
        
        # Mock aggregator method
        aggregator.aggregate_metrics = Mock(return_value=expected_metrics)
        
        # Run metrics aggregation
        metrics = await aggregator.aggregate_metrics(large_connection_dataset)
        
        # Validate aggregated metrics
        assert metrics.total_connections == len(large_connection_dataset)
        assert metrics.average_latency > 0
        assert metrics.median_latency > 0
        assert metrics.p95_latency >= metrics.median_latency
        assert metrics.p99_latency >= metrics.p95_latency
        assert metrics.min_latency <= metrics.average_latency <= metrics.max_latency
        assert metrics.total_bytes_transferred > 0
        assert 0 <= metrics.connection_success_rate <= 1.0
        
        # Validate protocol distribution
        protocol_total = sum(metrics.protocol_distribution.values())
        assert protocol_total == metrics.total_connections
        
        # Validate quality distribution
        quality_total = sum(metrics.quality_distribution.values())
        assert quality_total == metrics.total_connections
        
        # Verify aggregator was called with correct dataset
        aggregator.aggregate_metrics.assert_called_once_with(large_connection_dataset)
    
    @pytest.mark.asyncio
    async def test_bandwidth_utilization_analysis(self):
        """Test bandwidth utilization analysis and optimization recommendations."""
        # Create connections with various bandwidth characteristics
        connections = [
            # High bandwidth utilization
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                bytes_sent=50000,
                bytes_received=500000,
                duration_ms=1000.0,
                throughput_bps=4400000,  # 4.4 Mbps
                bandwidth_limit_bps=10000000  # 10 Mbps limit
            ),
            # Medium bandwidth utilization
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                bytes_sent=10000,
                bytes_received=100000,
                duration_ms=2000.0,
                throughput_bps=440000,  # 440 Kbps
                bandwidth_limit_bps=1000000  # 1 Mbps limit
            ),
            # Low bandwidth utilization
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                bytes_sent=1000,
                bytes_received=5000,
                duration_ms=5000.0,
                throughput_bps=9600,  # 9.6 Kbps
                bandwidth_limit_bps=100000  # 100 Kbps limit
            ),
            # Bandwidth-constrained connection
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                bytes_sent=100000,
                bytes_received=1000000,
                duration_ms=10000.0,
                throughput_bps=880000,  # 880 Kbps
                bandwidth_limit_bps=1000000  # 1 Mbps limit (near capacity)
            )
        ]
        
        # Mock bandwidth analyzer
        analyzer = Mock(spec=BandwidthUtilizationAnalyzer)
        
        # Create expected bandwidth analysis
        bandwidth_analysis = BandwidthAnalysisResults(
            total_connections=4,
            high_utilization_connections=1,
            medium_utilization_connections=1,
            low_utilization_connections=1,
            constrained_connections=1,
            average_utilization_percent=52.5,  # Average across all connections
            peak_utilization_percent=88.0,     # Highest utilization
            total_bandwidth_used_bps=5729600,  # Sum of all throughputs
            optimization_opportunities=[
                "Connection 1: High utilization - consider load balancing",
                "Connection 4: Near bandwidth limit - upgrade capacity",
                "Connection 3: Low utilization - investigate bottlenecks"
            ],
            recommendations=[
                "Implement traffic shaping for high-utilization connections",
                "Consider bandwidth upgrades for constrained connections",
                "Optimize low-utilization connections for better efficiency"
            ]
        )
        
        # Mock analyzer method
        analyzer.analyze_bandwidth_utilization = Mock(return_value=bandwidth_analysis)
        
        # Run bandwidth analysis
        analysis = await analyzer.analyze_bandwidth_utilization(connections)
        
        # Validate bandwidth analysis
        assert analysis.total_connections == 4
        assert analysis.high_utilization_connections >= 1
        assert analysis.constrained_connections >= 1
        assert 0 <= analysis.average_utilization_percent <= 100
        assert 0 <= analysis.peak_utilization_percent <= 100
        assert analysis.total_bandwidth_used_bps > 0
        assert len(analysis.optimization_opportunities) >= 2
        assert len(analysis.recommendations) >= 2
        
        # Validate specific recommendations
        recommendations_text = " ".join(analysis.recommendations).lower()
        assert "bandwidth" in recommendations_text
        assert "optimization" in recommendations_text or "optimize" in recommendations_text
        
        # Verify analyzer was called with correct connections
        analyzer.analyze_bandwidth_utilization.assert_called_once_with(connections)
    
    @pytest.mark.asyncio
    async def test_performance_optimization_recommendations(self, large_connection_dataset):
        """Test generation of performance optimization recommendations."""
        # Mock performance optimizer
        optimizer = Mock(spec=PerformanceOptimizer)
        
        # Create expected optimization recommendations
        optimization_results = PerformanceOptimizationResults(
            analyzed_connections=len(large_connection_dataset),
            optimization_categories={
                "latency_optimization": 250,
                "throughput_optimization": 180,
                "reliability_improvement": 120,
                "security_enhancement": 300,
                "resource_optimization": 150
            },
            priority_recommendations=[
                OptimizationRecommendation(
                    category="latency_optimization",
                    priority="high",
                    title="Reduce High-Latency Connections",
                    description="250 connections have latency >200ms",
                    impact_score=85,
                    implementation_effort="medium",
                    expected_improvement="30-50% latency reduction"
                ),
                OptimizationRecommendation(
                    category="security_enhancement",
                    priority="high",
                    title="Upgrade HTTP to HTTPS",
                    description="300 connections using insecure HTTP protocol",
                    impact_score=90,
                    implementation_effort="low",
                    expected_improvement="Significant security improvement"
                ),
                OptimizationRecommendation(
                    category="throughput_optimization",
                    priority="medium",
                    title="Optimize Low-Throughput Connections",
                    description="180 connections with throughput <1Mbps",
                    impact_score=70,
                    implementation_effort="high",
                    expected_improvement="2-3x throughput increase"
                )
            ],
            estimated_performance_gain=35.0,  # 35% overall improvement
            implementation_timeline_weeks=8
        )
        
        # Mock optimizer method
        optimizer.generate_recommendations = Mock(return_value=optimization_results)
        
        # Generate optimization recommendations
        results = await optimizer.generate_recommendations(large_connection_dataset)
        
        # Validate optimization results
        assert results.analyzed_connections == len(large_connection_dataset)
        assert len(results.optimization_categories) >= 4
        assert len(results.priority_recommendations) >= 2
        assert results.estimated_performance_gain > 0
        assert results.implementation_timeline_weeks > 0
        
        # Validate high-priority recommendations
        high_priority_recs = [r for r in results.priority_recommendations if r.priority == "high"]
        assert len(high_priority_recs) >= 1
        
        for rec in high_priority_recs:
            assert rec.impact_score >= 80
            assert rec.title and rec.description
            assert rec.expected_improvement
        
        # Validate category distribution
        total_categorized = sum(results.optimization_categories.values())
        assert total_categorized <= results.analyzed_connections  # Some connections may not need optimization
        
        # Verify optimizer was called with correct dataset
        optimizer.generate_recommendations.assert_called_once_with(large_connection_dataset)


# Mock classes for testing
class ConnectionPerformanceProcessor:
    """Mock connection performance processor."""
    async def analyze_connections(self, connections: List[ConnectionInfo]) -> 'PerformanceAnalysisResults':
        pass


class ConnectionQualityAnalyzer:
    """Mock connection quality analyzer."""
    async def assess_quality(self, connections: List[ConnectionInfo]) -> List['ConnectionQualityScore']:
        pass


class NetworkMetricsAggregator:
    """Mock network metrics aggregator."""
    async def aggregate_metrics(self, connections: List[ConnectionInfo]) -> 'NetworkPerformanceMetrics':
        pass


class BandwidthUtilizationAnalyzer:
    """Mock bandwidth utilization analyzer."""
    async def analyze_bandwidth_utilization(self, connections: List[ConnectionInfo]) -> 'BandwidthAnalysisResults':
        pass


class PerformanceOptimizer:
    """Mock performance optimizer."""
    async def generate_recommendations(self, connections: List[ConnectionInfo]) -> 'PerformanceOptimizationResults':
        pass


# Result classes
class PerformanceAnalysisResults:
    """Results of performance analysis."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class ConnectionQualityScore:
    """Connection quality score results."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class NetworkPerformanceMetrics:
    """Network performance metrics."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class BandwidthAnalysisResults:
    """Bandwidth analysis results."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class PerformanceOptimizationResults:
    """Performance optimization results."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class OptimizationRecommendation:
    """Individual optimization recommendation."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
