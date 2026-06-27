"""
analysis/__init__.py
=====================
Network Traffic Analysis and Intrusion Detection System

Traffic Analysis Package.

Houses components for computing traffic statistics, breaking down
protocol distributions, monitoring bandwidth utilisation in real time,
detecting network bottlenecks, and scoring network health/quality.

Modules:
    traffic_statistics  — Aggregate packet/byte counts and flow metrics
    protocol_analysis   — Protocol distribution and anomaly flagging
    bandwidth_monitor   — Real-time bandwidth utilisation tracking
    bottleneck_detector — Full Phase 4 congestion detection engine
    health_monitor      — Composite network health scoring (0–100)
    network_quality     — Five-dimension network quality estimation

Phase 3 additions:
    ProtocolAnalysis    — Full Phase 3 protocol analytics engine
    BandwidthMonitor    — Extended with Phase 3 historical analytics

Phase 4 additions:
    NetworkHealthMonitor    — Composite health score (0–100)
    BottleneckDetector      — Full Phase 4 congestion detection engine
    NetworkQualityAnalyzer  — Five-dimension quality index

Author: Network Traffic Analyzer Project
Version: 4.0.0
"""

from analysis.traffic_statistics import TrafficStatistics
from analysis.protocol_analysis import ProtocolAnalyzer, ProtocolAnalysis
from analysis.bandwidth_monitor import BandwidthMonitor
from analysis.bottleneck_detector import BottleneckDetector, BottleneckEvent, Severity
from analysis.health_monitor import NetworkHealthMonitor, NetworkHealthReport, HealthConfig
from analysis.network_quality import NetworkQualityAnalyzer, QualityReport

__all__ = [
    # Phase 3
    "TrafficStatistics",
    "ProtocolAnalyzer",          # Phase 1 legacy stub
    "ProtocolAnalysis",          # Phase 3 full engine
    "BandwidthMonitor",
    # Phase 4
    "BottleneckDetector",
    "BottleneckEvent",
    "Severity",
    "NetworkHealthMonitor",
    "NetworkHealthReport",
    "HealthConfig",
    "NetworkQualityAnalyzer",
    "QualityReport",
]
