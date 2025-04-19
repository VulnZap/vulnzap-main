import fs from 'fs'

export async function checkInit() {
    const vulnzapLocation = process.cwd() + '/.vulnzap-core';
    if (!fs.existsSync(vulnzapLocation)) {
      return false;
    }
    return true;
  }