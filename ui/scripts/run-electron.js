const { spawn } = require('child_process');
const path = require('path');
const electronBinary = require('electron');

const appDir = path.join(__dirname, '..');

// Ensure Electron doesn't run in Node-only mode.
delete process.env.ELECTRON_RUN_AS_NODE;

const child = spawn(electronBinary, ['.'], {
  cwd: appDir,
  stdio: 'inherit',
  env: process.env
});

child.on('error', (err) => {
  console.error('Failed to launch Electron:', err);
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code == null ? 0 : code);
});
