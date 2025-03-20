import { Client as McpClient } from '@modelcontextprotocol/sdk/dist/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/dist/client/stdio.js';
import { spawn } from 'child_process';
import { setTimeout } from 'timers/promises';

async function main() {
  // Start the MCP server as a child process with environment variables
  console.log("Starting VulnZap MCP server with NVD and GitHub integration...");
  const serverProcess = spawn('node', ['index.js'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NVD_API_KEY: 'YOUR_NVD_API_KEY',
      GITHUB_TOKEN: 'YOUR_GITHUB_TOKEN',
      USE_NVD: 'true'
    }
  });
  
  // Log server output
  serverProcess.stdout.on('data', (data) => {
    console.log(`Server: ${data.toString().trim()}`);
  });
  
  serverProcess.stderr.on('data', (data) => {
    console.error(`Server error: ${data.toString().trim()}`);
  });
  
  // Wait for server to start
  await setTimeout(2000);
  
  // Create and configure MCP client
  console.log("Connecting client to MCP server...");
  const transport = new StdioClientTransport(serverProcess.stdin, serverProcess.stdout);
  const client = new McpClient(transport);
  
  try {
    // Connect to the server
    await client.connect();
    console.log("Connected to MCP server!");
    
    // Test 1: Check a vulnerable package
    console.log("\nTest 1: Checking vulnerable package");
    const vulnUrl = "vuln://npm/express/4.16.0";
    const result1 = await client.fetch(vulnUrl);
    console.log("Result:");
    console.log(result1.contents[0].text);
    
    // Test 2: Check a safe package
    console.log("\nTest 2: Checking safe package");
    const safeUrl = "vuln://pip/flask/2.0.0";
    const result2 = await client.fetch(safeUrl);
    console.log("Result:");
    console.log(result2.contents[0].text);
    
    // Test 3: Check a well-known vulnerable package from NVD
    console.log("\nTest 3: Checking a well-known vulnerable package (should find in NVD)");
    const nvdUrl = "vuln://npm/lodash/4.17.15";  // CVE-2020-8203
    const result3 = await client.fetch(nvdUrl);
    console.log("Result:");
    console.log(result3.contents[0].text);
    
    // Test 4: Use batch-scan tool
    console.log("\nTest 4: Using batch-scan tool");
    const batchResult = await client.invoke("batch-scan", {
      apiKey: "test123",
      packages: [
        { ecosystem: "npm", packageName: "express", packageVersion: "4.16.0" },
        { ecosystem: "npm", packageName: "lodash", packageVersion: "4.17.15" },
        { ecosystem: "pip", packageName: "flask", packageVersion: "2.0.0" }
      ]
    });
    console.log("Result:");
    console.log(batchResult.content[0].text);
    
    // Test 5: Use detailed-report tool
    console.log("\nTest 5: Using detailed-report tool");
    const reportResult = await client.invoke("detailed-report", {
      apiKey: "test123",
      ecosystem: "npm",
      packageName: "lodash",
      packageVersion: "4.17.15"
    });
    console.log("Result:");
    console.log(reportResult.content[0].text);
    
    // Test 6: Trigger database refresh
    console.log("\nTest 6: Refreshing vulnerability database");
    const refreshResult = await client.invoke("refresh-database", {
      apiKey: "test123"
    });
    console.log("Result:");
    console.log(refreshResult.content[0].text);
    
    // Test 7: Code scanning
    console.log("\nTest 7: Scanning code for vulnerabilities");
    const javascriptCode = `
import express from 'express';
import axios from 'axios';
import lodash from 'lodash';

const app = express();
app.use(express.json());

app.get('/api/data', async (req, res) => {
  try {
    const response = await axios.get('https://api.example.com/data');
    const processed = lodash.merge({}, response.data, req.query);
    res.json(processed);
  } catch (error) {
    res.status(500).send('Error');
  }
});

app.listen(3000);
    `;
    
    const scanResult = await client.invoke("scan-code", {
      apiKey: "test123",
      code: javascriptCode,
      language: "javascript"
    });
    console.log("Result:");
    console.log(scanResult.content[0].text);
    
    console.log("\nAll tests completed successfully!");
  } catch (error) {
    console.error("Error:", error);
  } finally {
    // Clean up
    console.log("\nDisconnecting and shutting down...");
    await client.disconnect();
    serverProcess.kill();
    console.log("Done!");
  }
}

main().catch(console.error); 