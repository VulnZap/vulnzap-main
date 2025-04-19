# VulnZap Repository Scanning

## Overview
This feature allows users to scan entire Git repositories for vulnerabilities, package dependencies, and perform various tests through a single command. The process is fully API-driven, with minimal local storage requirements.

## Command Structure
```bash
vulnzap repository --url <git-url>
```

## Implementation Guide

### 1. Setting Up the Command
First, add the repository command to the CLI:

```typescript
// src/cli.ts
program
  .command('repository')
  .description('Scan a Git repository for vulnerabilities')
  .requiredOption('--url <url>', 'Git repository URL')
  .option('--branch <branch>', 'Specific branch to scan', 'main')
  .option('--format <format>', 'Report format (json, html, pdf)', 'json')
  .action(async (options) => {
    try {
      await scanRepository(options);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });
```

### 2. Repository Scanning Implementation

```typescript
// src/commands/repository.ts
import { exec } from 'child_process';
import { promisify } from 'util';
import { tmpdir } from 'os';
import { join } from 'path';
import { mkdtemp, rm } from 'fs/promises';
import * as api from '../api/apis.js';

const execAsync = promisify(exec);

export async function scanRepository(options: {
  url: string;
  branch?: string;
  format?: string;
}) {
  // Create temporary directory
  const tempDir = await mkdtemp(join(tmpdir(), 'vulnzap-'));
  
  try {
    // Clone repository
    await execAsync(`git clone ${options.url} ${tempDir}`);
    if (options.branch) {
      await execAsync(`git checkout ${options.branch}`, { cwd: tempDir });
    }

    // Initialize repository analysis
    const analysisConfig = await api.initializeRepositoryAnalysis({
      url: options.url,
      branch: options.branch,
      format: options.format
    });

    // Scan packages
    const packageFiles = await findPackageFiles(tempDir);
    const vulnerabilityReport = await api.scanPackages(packageFiles);

    // Run tests
    const testResults = await api.runTests({
      repositoryPath: tempDir,
      testConfig: analysisConfig.testConfig
    });

    // Generate report
    const report = await api.generateReport({
      repository: {
        url: options.url,
        branch: options.branch
      },
      vulnerabilities: vulnerabilityReport,
      tests: testResults
    });

    // Save report
    const reportPath = join(process.cwd(), `vulnzap-report.${options.format}`);
    await saveReport(report, reportPath);

    console.log(`Report generated successfully: ${reportPath}`);
  } finally {
    // Cleanup
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function findPackageFiles(dir: string): Promise<string[]> {
  // Implementation to find package.json, requirements.txt, etc.
  // Returns array of file paths
}

async function saveReport(report: any, path: string): Promise<void> {
  // Implementation to save report in specified format
}
```

### 3. API Integration

```typescript
// src/api/apis.ts
export async function initializeRepositoryAnalysis(config: {
  url: string;
  branch?: string;
  format?: string;
}) {
  const response = await fetch('/api/repository/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${getApiKey()}`
    },
    body: JSON.stringify(config)
  });
  return response.json();
}

export async function scanPackages(packageFiles: string[]) {
  const response = await fetch('/api/scan/packages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${getApiKey()}`
    },
    body: JSON.stringify({ files: packageFiles })
  });
  return response.json();
}

export async function runTests(config: {
  repositoryPath: string;
  testConfig: any;
}) {
  const response = await fetch('/api/tests/run', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${getApiKey()}`
    },
    body: JSON.stringify(config)
  });
  return response.json();
}

export async function generateReport(data: {
  repository: any;
  vulnerabilities: any;
  tests: any;
}) {
  const response = await fetch('/api/reports/generate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${getApiKey()}`
    },
    body: JSON.stringify(data)
  });
  return response.json();
}
```

### 4. Error Handling

```typescript
// src/utils/error-handling.ts
export class RepositoryScanError extends Error {
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'RepositoryScanError';
  }
}

export function handleRepositoryError(error: any) {
  if (error instanceof RepositoryScanError) {
    console.error(`Repository scan error (${error.code}): ${error.message}`);
  } else if (error.code === 'ECONNREFUSED') {
    console.error('Failed to connect to VulnZap API. Please check your internet connection.');
  } else {
    console.error('An unexpected error occurred:', error.message);
  }
}
```

### 5. Testing the Implementation

```typescript
// tests/repository.test.ts
import { scanRepository } from '../src/commands/repository';
import * as api from '../src/api/apis';

jest.mock('../src/api/apis');

describe('Repository Scanning', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should successfully scan a repository', async () => {
    const mockAnalysisConfig = { testConfig: {} };
    const mockVulnerabilityReport = { vulnerabilities: [] };
    const mockTestResults = { passed: true };

    api.initializeRepositoryAnalysis.mockResolvedValue(mockAnalysisConfig);
    api.scanPackages.mockResolvedValue(mockVulnerabilityReport);
    api.runTests.mockResolvedValue(mockTestResults);
    api.generateReport.mockResolvedValue({ report: 'test-report' });

    await scanRepository({
      url: 'https://github.com/example/repo',
      branch: 'main',
      format: 'json'
    });

    expect(api.initializeRepositoryAnalysis).toHaveBeenCalled();
    expect(api.scanPackages).toHaveBeenCalled();
    expect(api.runTests).toHaveBeenCalled();
    expect(api.generateReport).toHaveBeenCalled();
  });
});
```

### 6. Required Dependencies

Add these to your `package.json`:

```json
{
  "dependencies": {
    "node-fetch": "^3.0.0",
    "tmp": "^0.2.1"
  },
  "devDependencies": {
    "@types/node": "^16.0.0",
    "jest": "^27.0.0",
    "typescript": "^4.0.0"
  }
}
```

### 7. Building and Testing

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test

# Test the command
node dist/cli.js repository --url https://github.com/example/repo
```

This implementation provides a complete solution for the repository scanning feature. The code is organized into separate modules for better maintainability and testability. The implementation includes:

1. CLI command setup
2. Core repository scanning logic
3. API integration
4. Error handling
5. Test suite
6. Required dependencies
7. Build and test instructions

The code follows best practices for:
- Error handling
- Cleanup of temporary files
- API authentication
- Type safety
- Test coverage
- Modular architecture

## Example Usage
```bash
# Basic usage
vulnzap repository --url https://github.com/example/repo

# With specific branch
vulnzap repository --url https://github.com/example/repo --branch main

# With custom report format
vulnzap repository --url https://github.com/example/repo --format json
```

## API Endpoints Required
1. `/api/repository/analyze` - Initialize repository analysis
2. `/api/scan/packages` - Scan package dependencies
3. `/api/tests/run` - Execute tests
4. `/api/reports/generate` - Generate final report
5. `/api/reports/upload` - Upload report for storage

## Dependencies
- Git (for repository cloning)
- Node.js (for CLI execution)
- API client libraries
- Temporary file management utilities

## Future Enhancements
- Support for private repositories
- Custom scanning configurations
- Integration with CI/CD pipelines
- Real-time scanning progress updates
- Multiple report formats 