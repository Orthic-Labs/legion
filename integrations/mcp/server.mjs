#!/usr/bin/env node
// Read-only stdio MCP server per SNIP-MCP-01. stdout carries protocol frames
// only; logs go to stderr. Implements the MCP initialize/tools/list and
// tools/call JSON-RPC methods over stdio without a network listener.

import { listTools, callTool } from './tools.mjs';
import { LEGION_VERSION } from '../../lib/version.mjs';

const PROTOCOL_VERSION = '2024-11-05';

function send(response) {
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

function handleRequest(request) {
  const { id, method, params } = request ?? {};
  if (method === 'initialize') {
    send({
      jsonrpc: '2.0', id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: 'legion', version: LEGION_VERSION },
      },
    });
    return;
  }
  if (method === 'tools/list') {
    send({ jsonrpc: '2.0', id, result: { tools: listTools() } });
    return;
  }
  if (method === 'tools/call') {
    pending += 1;
    callTool(params).then((result) => {
      send({ jsonrpc: '2.0', id, result });
    }).catch((error) => {
      send({ jsonrpc: '2.0', id, error: { code: -32603, message: error.message } });
    }).finally(() => {
      pending -= 1;
    });
    return;
  }
  if (method === 'notifications/initialized' || method === 'notifications/cancelled') {
    return; // notifications have no id and no response
  }
  send({ jsonrpc: '2.0', id, error: { code: -32601, message: `method not found: ${method}` } });
}

let buffer = '';
let pending = 0;
function processBuffer() {
  let newline;
  while ((newline = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);
    if (!line.trim()) continue;
    try {
      handleRequest(JSON.parse(line));
    } catch (error) {
      process.stderr.write(`invalid JSON-RPC frame: ${error.message}\n`);
    }
  }
}
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  processBuffer();
});
process.stdin.on('end', () => {
  // Handle any trailing buffered frame that lacks a final newline.
  processBuffer();
  if (buffer.trim()) {
    try {
      handleRequest(JSON.parse(buffer.trim()));
    } catch (error) {
      process.stderr.write(`invalid JSON-RPC frame: ${error.message}\n`);
    }
    buffer = '';
  }
  const deadline = Date.now() + 2000;
  const drain = setInterval(() => {
    if (pending === 0 || Date.now() > deadline) {
      clearInterval(drain);
      process.exit(0);
    }
  }, 25);
});
