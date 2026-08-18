import { AuthorityBindingStore } from '../../lib/authority-binding-store.mjs';
const [root, agentType = 'sage'] = process.argv.slice(2);
const store = new AuthorityBindingStore({ root });
console.log('ready');
process.stdin.once('data', () => { try { console.log(JSON.stringify(store.observe({ adapter: 'codex', sessionId: 'race-session', agentId: 'race-agent', agentType, eventId: 'hev_0123456789ABCDEFGHJKMNPQ' }))); }
catch (error) { console.log(JSON.stringify({ code: error.code })); process.exitCode = 1; }
});
