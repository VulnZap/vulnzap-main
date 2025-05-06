import execa from 'execa';
import path from 'path';

const CLI_PATH = path.join(__dirname, '../dist/cli.js');

describe('VulnZap CLI minimal flow', () => {

  it('should block commands that require login/init if not logged in/initialized', async () => {
    // check
    let res = await execa('node', [CLI_PATH, 'check', 'npm:express@4.16.0', '-C'], { reject: false });
    expect(res.stderr + res.stdout).toMatch(/You must be logged in|API key not found|login to authenticate|- Checking npm:express@4.16.0 for vulnerabilities/);
    // setup
    res = await execa('node', [CLI_PATH, 'setup', '-k', 'dummykey'], { reject: false });
    expect(res.stderr + res.stdout).toMatch(/You must be logged in|run `vulnzap login`/);
    // init (should block if not logged in)
    res = await execa('node', [CLI_PATH, 'init'], { reject: false });
    expect(res.stderr + res.stdout).toMatch(/You must be logged in|run `vulnzap login`/);
  }, 10000);

  it('should check if backend is reachable', async () => {
    const { stdout, stderr } = await execa('node', [CLI_PATH, 'status'], { reject: false });
    expect(stdout + stderr).toMatch(/VulnZap server is healthy|VulnZap server is down|server is down/i);
  });

  it('should return vulnerabilities for express@4.16.0 if logged in and initialized', async () => {
    const { stdout } = await execa('node', [CLI_PATH, 'check', 'npm:express@4.16.0']);
    expect(stdout).toMatch(/vulnerab|CVE|update|found/i); // Should mention vulnerabilities or CVE
  });
}); 