// Vulnerable Tauri frontend - demonstrates common security issues in Tauri JS code

import { invoke } from '@tauri-apps/api';
import { Command } from '@tauri-apps/api/shell';

// VULN: Shell Command.create from frontend with user input
async function runUserCommand(userInput) {
  const cmd = Command.create('my-sidecar', [userInput]);
  const output = await cmd.execute();
  return output.stdout;
}

// VULN: Direct shell plugin invocation
async function executeShell(program, args) {
  const result = await invoke("plugin:shell|execute", {
    program: program,
    args: args,
  });
  return result;
}

// VULN: invoke with variable command name from user input
async function dynamicInvoke(commandName, payload) {
  const result = await invoke(commandName, payload);
  return result;
}

// VULN: invoke with DOM-sourced command name
async function invokeFromInput() {
  const cmdName = document.getElementById('command-input').value;
  const result = await invoke(cmdName);
  document.getElementById('output').textContent = result;
}

// VULN: Exposing __TAURI__ to iframe via postMessage
function bridgeToIframe(iframe) {
  iframe.contentWindow.postMessage(window.__TAURI__, '*');
}

// VULN: Using __TAURI__ with innerHTML
async function unsafeRender(path) {
  const content = await window.__TAURI__.fs.readTextFile(path);
  document.getElementById('content').innerHTML = window.__TAURI__.fs.readTextFile(path);
}

// VULN: Fetching via tauri://localhost protocol directly
async function directProtocolAccess(path) {
  const response = await fetch(`tauri://localhost/${path}`);
  return response.text();
}

export {
  runUserCommand,
  executeShell,
  dynamicInvoke,
  invokeFromInput,
  bridgeToIframe,
  unsafeRender,
  directProtocolAccess,
};
