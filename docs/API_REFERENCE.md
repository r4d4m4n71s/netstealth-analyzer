# 📚 NetStealth Analyzer v2.0 - API Reference

**Version**: 2.0.0  
**Python**: 3.13+  
**Architecture**: Async-first, Event-driven  

---

## 🚀 Quick Start

### Basic Usage

```python
import asyncio
from netstealth_analyzer import NetStealthAnalyzer

async def analyze_session():
    # Create analyzer with fluent API
    analyzer = (NetStealthAnalyzer.create()
                .with_logs("session.har")
                .for_service("example.com")
                .track_progress(lambda event, data: print(f"Progress: {data}"))
                .build())
    
    # Run analysis
    result = await analyzer.analyze()
    
    # Generate report
    await analyzer.report(result, format="html", output="report.html")

asyncio.run(analyze_session())
```

---

## 🏗️ Core API

### NetStealthAnalyzer

The main entry point for the NetStealth Analyzer framework.

#### Class Methods

##### `create() -> AnalyzerBuilder`

Creates a new analyzer builder for fluent API configuration.

```python
analyzer = NetStealthAnalyzer.create()
```

**Returns**: `AnalyzerBuilder` instance for method chaining

---

### AnalyzerBuilder

Fluent API builder for configuring the analyzer.

#### Methods

##### `with_logs(files: Union[str, Path, List[Union[str, Path]]]) -> AnalyzerBuilder`

Add log files for analysis.

```python
# Single file
analyzer.with_logs("session.har")

# Multiple files
analyzer.with_logs([
    "session.har",
    "mitmproxy.log",
    "browser_automation.log"
])
```

**Parameters**:
- `files`: Path(s) to log files (HAR, Mitmproxy, Browser logs)

**Returns**: `AnalyzerBuilder` for method chaining

##### `for_service(domains: Union[str, List[str]]) -> AnalyzerBuilder`

Set target service domains for analysis.

```python
# Single domain
analyzer.for_service("example.com")

# Multiple domains
analyzer.for_service(["example.com", "api.service.com"])
```

**Parameters**:
- `domains`: Target domain(s) to analyze

**Returns**: `AnalyzerBuilder` for method chaining

##### `with_detectors(*detector_names: str) -> AnalyzerBuilder`

Configure which detectors to use by name from the global registry.

```python
# Specific detectors
analyzer.with_detectors("proxy", "browser", "network")

# Single detector
analyzer.with_detectors("proxy")
```

**Parameters**:
- `*detector_names`: Variable number of detector names

**Available Detectors**:
- `"proxy"`: Proxy detection
- `"browser"`: Browser automation detection
- `"network"`: Network anomaly detection
- `"tls"`: TLS analysis

**Returns**: `AnalyzerBuilder` for method chaining

**Note**: This method creates detector instances from the global detector registry and adds them using `with_detector()`.

##### `track_progress(callback: Callable[[AnalysisEvent, Any], None]) -> AnalyzerBuilder`

Set progress tracking callback.

```python
def progress_handler(event, data):
    if hasattr(data, 'percentage'):
        print(f"Progress: {data.percentage:.1f}%")

analyzer.track_progress(progress_handler)
```

**Parameters**:
- `callback`: Function to handle progress events

**Returns**: `AnalyzerBuilder` for method chaining

##### `on_event(event: AnalysisEvent, handler: EventHandler) -> AnalyzerBuilder`

Add event handler for specific events.

```python
async def on_issue_found(event, data):
    print(f"🚨 Issue: {data.title} (Severity: {data.severity})")

analyzer.on_event(AnalysisEvent.ISSUE_FOUND, on_issue_found)
```

**Parameters**:
- `event`: Event type to handle
- `handler`: Async function to handle the event

**Returns**: `AnalyzerBuilder` for method chaining

##### `build() -> NetStealthAnalyzer`

Build the configured analyzer.

```python
built_analyzer = analyzer.build()
```

**Returns**: Configured `NetStealthAnalyzer` instance

---

### NetStealthAnalyzer (Built Instance)

The configured analyzer instance ready for analysis.

#### Methods

##### `async analyze() -> AnalysisResult`

Run complete analysis on configured log files.

```python
result = await analyzer.analyze()
```

**Returns**: `AnalysisResult` with findings and statistics

**Raises**:
- `FileNotFoundError`: If log files don't exist
- `ValueError`: If log format is invalid
- `AnalysisError`: If analysis fails

##### `async stream_analyze() -> AsyncIterator[Issue]`

Stream analysis results as they're found.

```python
async for issue in analyzer.stream_analyze():
    print(f"Found: {issue.title}")
```

**Yields**: `Issue` objects as they're detected

##### `async report(result: AnalysisResult, format: str, output: str) -> None`

Generate analysis report.

```python
await analyzer.report(result, format="html", output="report.html")
```

**Parameters**:
- `result`: Analysis result to report
- `format`: Output format ("json", "html", "markdown", "yaml")
- `output`: Output file path

**Supported Formats**:
- `"json"`: JSON format
- `"html"`: HTML report with styling
- `"markdown"`: Markdown format
- `"yaml"`: YAML format

---

## 📊 Data Models

### AnalysisResult

Contains the complete analysis results.

```python
@dataclass
class AnalysisResult:
    issues_found: List[Issue]
    network_traces: List[NetworkTrace]
    statistics: Dict[str, Any]
    execution_context: ExecutionContext
    performance_metrics: PerformanceMetrics
```

**Attributes**:
- `issues_found`: List of detected security issues
- `network_traces`: Network routing information
- `statistics`: Analysis statistics
- `execution_context`: Analysis context
- `performance_metrics`: Performance data

### Issue

Represents a detected security issue.

```python
@dataclass
class Issue:
    id: str
    title: str
    description: str
    severity: IssueSeverity
    category: IssueCategory
    confidence: float
    evidence: List[IssueEvidence]
    remediation: List[RemediationSuggestion]
    affected_urls: List[str]
    risk_score: float
```

**Attributes**:
- `id`: Unique issue identifier
- `title`: Issue title
- `description`: Detailed description
- `severity`: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
- `category`: Issue category
- `confidence`: Detection confidence (0.0-1.0)
- `evidence`: Supporting evidence
- `remediation`: Suggested fixes
- `affected_urls`: URLs affected by the issue
- `risk_score`: Calculated risk score

### NetworkTrace

Network routing information.

```python
@dataclass
class NetworkTrace:
    trace_id: str
    hops: List[NetworkHop]
    metadata: Dict[str, Any]
    timestamp: datetime
```

**Attributes**:
- `trace_id`: Unique trace identifier
- `hops`: Network routing hops
- `metadata`: Additional trace data (HTTP data stored here for parsers)
- `timestamp`: Trace timestamp

### NetworkHop

Individual network routing hop.

```python
@dataclass
class NetworkHop:
    hop_number: int
    actor: str
    actor_name: str
    incoming_ip: str
    outgoing_ip: str
    connection_info: Optional[ConnectionInfo]
    tls_info: Optional[TLSInfo]
    proxy_info: Optional[ProxyInfo]
    geographic_info: Optional[GeographicInfo]
    anomalies: List[str]
    risk_level: RiskLevel
```

---

## 🎯 Event System

### AnalysisEvent

Available events for monitoring analysis progress.

```python
class AnalysisEvent(Enum):
    # Analysis Lifecycle
    ANALYSIS_STARTED = auto()
    ANALYSIS_COMPLETED = auto()
    ANALYSIS_FAILED = auto()
    ANALYSIS_CANCELLED = auto()
    
    # Progress Events
    PROGRESS_UPDATE = auto()
    STAGE_STARTED = auto()
    STAGE_COMPLETED = auto()
    STAGE_FAILED = auto()
    
    # Parsing Events
    PARSER_STARTED = auto()
    PARSER_COMPLETED = auto()
    PARSER_FAILED = auto()
    LOG_ENTRY_PARSED = auto()
    
    # Detection Events
    DETECTOR_STARTED = auto()
    DETECTOR_COMPLETED = auto()
    DETECTOR_FAILED = auto()
    ISSUE_FOUND = auto()
    ISSUE_RESOLVED = auto()
    
    # Reporting Events
    REPORT_STARTED = auto()
    REPORT_COMPLETED = auto()
    REPORT_CHUNK_READY = auto()
```

### Event Handlers

Event handlers are async functions that receive event data.

```python
async def event_handler(event: AnalysisEvent, data: Any) -> None:
    """Handle analysis events."""
    if event == AnalysisEvent.ISSUE_FOUND:
        issue_data = data  # IssueData instance
        print(f"Issue found: {issue_data.title}")
    elif event == AnalysisEvent.PROGRESS_UPDATE:
        progress_data = data  # ProgressData instance
        print(f"Progress: {progress_data.percentage:.1f}%")
```

---

## 🔍 Parsers

### Supported Log Formats

#### HAR Files (.har, .json)

HTTP Archive format with complete request/response data.

```python
from netstealth_analyzer.parsers.har import HarParser

parser = HarParser()
result = await parser.parse("session.har")
```

**Features**:
- Complete HTTP request/response extraction
- Timing information analysis
- TLS handshake data
- Proxy header detection
- Large file streaming support

#### Mitmproxy Logs (.log)

Mitmproxy debug log format.

```python
from netstealth_analyzer.parsers.mitmproxy import MitmproxyParser

parser = MitmproxyParser()
result = await parser.parse("mitmproxy.log")
```

**Features**:
- Request/response correlation
- Connection tracking
- Proxy flow analysis
- Error handling for incomplete flows

---

## 🕵️ Detectors

### Proxy Detector

Detects proxy usage through various indicators.

```python
from netstealth_analyzer.detectors.proxy import ProxyDetector

detector = ProxyDetector()
result = await detector.detect(context)
```

**Detection Methods**:
- HTTP headers analysis (X-Forwarded-For, Via, etc.)
- IP geolocation inconsistencies
- WebRTC leak detection
- Datacenter IP identification
- VPN service detection
- DNS leak analysis

### Browser Detector

Detects browser automation and fingerprinting.

```python
from netstealth_analyzer.detectors.browser import BrowserDetector

detector = BrowserDetector()
result = await detector.detect(context)
```

**Detection Methods**:
- Selenium WebDriver detection
- Headless browser identification
- Automation framework patterns
- JavaScript fingerprinting
- User agent analysis
- Behavioral pattern analysis

### Network Detector

Analyzes network routing and anomalies.

```python
from netstealth_analyzer.detectors.network import NetworkDetector

detector = NetworkDetector()
result = await detector.detect(context)
```

**Detection Methods**:
- Unusual routing patterns
- Geographic inconsistencies
- Latency analysis
- Proxy chain detection
- Tor exit node identification
- Security service detection

---

## 📝 Reporting

### Report Formats

#### JSON Report

Machine-readable JSON format.

```python
await analyzer.report(result, format="json", output="report.json")
```

#### HTML Report

Styled HTML report with interactive elements.

```python
await analyzer.report(result, format="html", output="report.html")
```

#### Markdown Report

Human-readable markdown format.

```python
await analyzer.report(result, format="markdown", output="report.md")
```

#### YAML Report

Structured YAML format.

```python
await analyzer.report(result, format="yaml", output="report.yaml")
```

---

## 🔧 Advanced Usage

### Custom Event Handling

```python
import asyncio
from netstealth_analyzer import NetStealthAnalyzer
from netstealth_analyzer.core.events import AnalysisEvent

async def advanced_analysis():
    analyzer = NetStealthAnalyzer.create()
    
    # Configure multiple log sources
    analyzer.with_logs([
        "session.har",
        "mitmproxy.log",
        "browser_automation.log"
    ])
    
    # Set service domains
    analyzer.for_service(["example.com", "api.service.com"])
    
    # Configure specific detectors
    analyzer.with_detectors(["proxy", "browser", "network"])
    
    # Add comprehensive event handling
    async def on_issue_found(event, data):
        severity_emoji = {
            "LOW": "ℹ️",
            "MEDIUM": "⚠️", 
            "HIGH": "🚨",
            "CRITICAL": "💥"
        }
        emoji = severity_emoji.get(data.severity, "❓")
        print(f"{emoji} {data.title} (Confidence: {data.confidence:.1%})")
    
    analyzer.on_event(AnalysisEvent.ISSUE_FOUND, on_issue_found)
    
    # Build and run analysis
    built_analyzer = analyzer.build()
    result = await built_analyzer.analyze()
    
    # Generate multiple report formats
    await built_analyzer.report(result, format="json", output="results.json")
    await built_analyzer.report(result, format="html", output="report.html")
    
    return result

# Run analysis
result = asyncio.run(advanced_analysis())
```

### Streaming Analysis

```python
async def streaming_analysis():
    analyzer = (NetStealthAnalyzer.create()
                .with_logs("large_session.har")
                .for_service("example.com")
                .build())
    
    # Process issues as they're found
    async for issue in analyzer.stream_analyze():
        if issue.severity in ["HIGH", "CRITICAL"]:
            print(f"🚨 Critical issue: {issue.title}")
        else:
            print(f"ℹ️ Issue: {issue.title}")

asyncio.run(streaming_analysis())
```

---

## 🚨 Error Handling

### Exception Types

#### AnalysisError

Base exception for analysis errors.

```python
from netstealth_analyzer.core.errors import AnalysisError

try:
    result = await analyzer.analyze()
except AnalysisError as e:
    print(f"Analysis failed: {e}")
```

#### ParsingError

Raised when log parsing fails.

```python
from netstealth_analyzer.core.errors import ParsingError

try:
    result = await parser.parse("invalid.har")
except ParsingError as e:
    print(f"Parsing failed: {e}")
```

---

## 🧪 Testing

### Unit Testing

```python
import pytest
from netstealth_analyzer import NetStealthAnalyzer

@pytest.mark.asyncio
async def test_basic_analysis():
    """Test basic analysis functionality."""
    analyzer = (NetStealthAnalyzer.create()
                .with_logs("test_session.har")
                .for_service("example.com")
                .build())
    
    result = await analyzer.analyze()
    
    assert result is not None
    assert len(result.issues_found) >= 0
    assert result.statistics is not None
```

---

## 📞 Support & Resources

### Documentation Links

- **GitHub Repository**: https://github.com/r4d4m4n71s/netstealth-analyzer
- **Issue Tracker**: https://github.com/r4d4m4n71s/netstealth-analyzer/issues

### Python Resources

- **Python 3.13 Documentation**: https://docs.python.org/3.13/
- **Asyncio Guide**: https://docs.python.org/3/library/asyncio.html
- **Pydantic v2**: https://docs.pydantic.dev/latest/

---

**API Reference v2.0** - Last Updated: September 17, 2025
