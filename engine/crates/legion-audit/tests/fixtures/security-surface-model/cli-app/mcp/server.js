const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');

const server = new McpServer({ name: 'fixture', version: '1.0.0' });

server.tool('search_docs', {}, async () => ({ content: [] }));
server.registerTool('delete_doc', {}, async () => ({ content: [] }));
