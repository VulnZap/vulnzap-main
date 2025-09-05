# 🚀 VulnZap SSE Implementation Guide

## Server-Sent Events (SSE) for Real-time Repository Scan Progress

### SSE Endpoint Implementation

```typescript
GET /api/scan/repo/{scanId}/events
Headers: {
  'x-api-key': '<user-api-key>',
  'Accept': 'text/event-stream',
  'Cache-Control': 'no-cache'
}
```

### Response Format

```javascript
// Set proper headers
res.setHeader('Content-Type', 'text/event-stream');
res.setHeader('Cache-Control', 'no-cache');
res.setHeader('Connection', 'keep-alive');
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Headers', 'Cache-Control');

// Send events in this format:
data: {"type":"progress","scanId":"scan_123","data":{"progress":{"current":100,"total":500,"percentage":20,"stage":"scanning-files"}},"timestamp":"2024-01-01T10:00:05Z"}

data: {"type":"vulnerability","scanId":"scan_123","data":{"vulnerability":{"severity":"HIGH","title":"Remote Code Execution","description":"..."}},"timestamp":"2024-01-01T10:01:15Z"}

data: {"type":"completed","scanId":"scan_123","data":{"message":"Scan completed successfully"},"timestamp":"2024-01-01T10:05:00Z"}
```

## Event Types Required

### 1. Progress Events
```json
{
  "type": "progress",
  "scanId": "scan_1234567890",
  "data": {
    "progress": {
      "current": 245,
      "total": 1200,
      "percentage": 20,
      "stage": "scanning-files"
    }
  },
  "timestamp": "2024-01-01T10:00:05Z"
}
```

### 2. Vulnerability Events
```json
{
  "type": "vulnerability",
  "scanId": "scan_1234567890",
  "data": {
    "vulnerability": {
      "severity": "HIGH",
      "title": "Remote Code Execution in package-x",
      "description": "Detailed vulnerability description...",
      "package": "package-x",
      "version": "1.2.3"
    }
  },
  "timestamp": "2024-01-01T10:01:15Z"
}
```

### 3. Completion Events
```json
{
  "type": "completed",
  "scanId": "scan_1234567890",
  "data": {
    "message": "Scan completed successfully",
    "totalFiles": 1200,
    "vulnerabilitiesFound": 3
  },
  "timestamp": "2024-01-01T10:05:00Z"
}
```

### 4. Failure Events
```json
{
  "type": "failed",
  "scanId": "scan_1234567890",
  "data": {
    "message": "Failed to clone repository",
    "error": "Repository not accessible",
    "stage": "initialization"
  },
  "timestamp": "2024-01-01T10:02:00Z"
}
```

## Implementation Steps

1. **Set up SSE endpoint** with proper headers
2. **Connect to scan job** using scanId from URL parameter
3. **Stream events** as scan progresses through stages:
   - `initializing` → `scanning-files` → `analyzing-dependencies` → `checking-vulnerabilities` → `completed`
4. **Send progress updates** at regular intervals (every 5-10 seconds)
5. **Emit vulnerability events** immediately when found
6. **Handle completion/failure** with appropriate final events
7. **Clean up connections** when scan ends or client disconnects

## Progress Stages

```typescript
const STAGES = [
  'initializing',      // Cloning repo, setting up
  'scanning-files',    // Counting/processing files
  'analyzing-deps',    // Parsing package.json, requirements.txt
  'checking-vulns',    // Cross-referencing with vuln databases
  'generating-report', // Finalizing results
  'completed'          // Scan finished
];
```

## Error Handling

- **Authentication**: Validate API key for SSE connections
- **Connection Limits**: Prevent too many concurrent SSE connections
- **Timeout Handling**: Close stale connections after inactivity
- **Scan Not Found**: Handle invalid scanId gracefully
- **Network Issues**: Robust error handling for connection failures

## Testing the SSE Stream

```bash
# Test with curl
curl -H "x-api-key: YOUR_API_KEY" \
     -H "Accept: text/event-stream" \
     "https://your-api.com/api/scan/repo/scan_123/events"
```

## CLI Integration

The CLI will automatically:
1. Try SSE first for real-time updates
2. Fall back to polling if SSE fails
3. Display progress bars and vulnerability alerts
4. Save results to JSON files for agent reading

## Example CLI Usage

```bash
# Real-time streaming (preferred)
vulnzap scan https://github.com/user/repo --wait --output results.json

# Output shows:
📊 Scanning files: 245/1200 (20%)
🚨 HIGH: Remote code execution vulnerability in package-x
✅ Scan completed!
```

This SSE implementation enables real-time, interactive repository scanning with live progress updates! 🎉
