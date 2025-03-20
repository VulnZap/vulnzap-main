#!/bin/bash

# Simple shell script wrapper for vulnzap-mcp
# This bypasses issues with dynamic module imports

# Parse arguments and set environment variables
while [[ $# -gt 0 ]]; do
  case $1 in
    --nvd-key)
      export NVD_API_KEY="$2"
      export USE_NVD=true
      echo "NVD integration enabled"
      shift 2
      ;;
    --github-token)
      export GITHUB_TOKEN="$2"
      echo "GitHub Advisory Database integration enabled"
      shift 2
      ;;
    --data-path)
      export DATA_PATH="$2"
      shift 2
      ;;
    --premium-key)
      export PREMIUM_API_KEY="$2"
      shift 2
      ;;
    --port)
      export PORT="$2"
      shift 2
      ;;
    --version|-v)
      node -e "console.log('VulnZap MCP v' + require('./package.json').version)"
      exit 0
      ;;
    --help|-h)
      cat << EOF
VulnZap MCP - Vulnerability scanning server for LLM integration

USAGE:
  vulnzap [options]

OPTIONS:
  --help, -h            Show this help message
  --port PORT           Set the server port (default: 3000)
  --nvd-key KEY         Set the NVD API key
  --github-token TOKEN  Set the GitHub API token
  --data-path PATH      Set the path to the advisories file
  --premium-key KEY     Set the premium API key
  --verbose             Enable verbose logging
  --version, -v         Show version information

EXAMPLES:
  vulnzap                                  # Start the server with default settings
  vulnzap --nvd-key YOUR_KEY               # Start with NVD integration
  vulnzap --github-token YOUR_TOKEN        # Start with GitHub integration
  vulnzap --nvd-key KEY --github-token KEY # Start with both NVD and GitHub
EOF
      exit 0
      ;;
    *)
      # Unknown option
      shift
      ;;
  esac
done

# Run the server directly
node index.js 