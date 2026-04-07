// Safe Tauri frontend - demonstrates secure patterns for Tauri JS code

import { invoke } from '@tauri-apps/api';

// SAFE: invoke with string literal command names
async function getData(id) {
  const result = await invoke('get_data', { id: id });
  return result;
}

// SAFE: invoke with fixed command name and validated params
async function saveDocument(title, content) {
  if (typeof title !== 'string' || title.length > 200) {
    throw new Error('Invalid title');
  }
  const result = await invoke('save_document', {
    title: title,
    content: content,
  });
  return result;
}

// SAFE: Using allowlist to map user selections to fixed invoke calls
async function executeAction(action, params) {
  switch (action) {
    case 'list':
      return await invoke('list_items', params);
    case 'detail':
      return await invoke('get_item_detail', params);
    case 'search':
      return await invoke('search_items', params);
    default:
      throw new Error('Unknown action: ' + action);
  }
}

// SAFE: Using textContent instead of innerHTML
async function displayResult(id) {
  const data = await invoke('get_data', { id: id });
  document.getElementById('output').textContent = data;
}

// SAFE: No __TAURI__ global access, using imports
async function readFile(path) {
  const result = await invoke('read_app_file', { filename: path });
  return result;
}

// SAFE: Communicating with iframes via structured data only
function sendToIframe(iframe, data) {
  const safePayload = {
    type: 'data-update',
    content: String(data),
  };
  iframe.contentWindow.postMessage(safePayload, window.location.origin);
}

export {
  getData,
  saveDocument,
  executeAction,
  displayResult,
  readFile,
  sendToIframe,
};
