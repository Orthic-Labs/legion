// Rust language bench: offline cargo command selection, unsafe boundary
// modeling, and Tauri config observations.
import rustPack, { unsafeBoundaries } from '../../../providers/native/rust/index.mjs';
import tauriPack from '../../../providers/frameworks/tauri/index.mjs';

const commands = rustPack.commands({ root: '/repo', files: ['src/main.rs'], manifests: ['Cargo.toml'], profile: 'standard' });
const boundaries = unsafeBoundaries(['src/lib.rs'], () => 'unsafe { ffi() }\nextern "C" { fn c(); }');
const tauriObs = tauriPack.analyze({
  files: ['tauri.conf.json'],
  readFile: () => '{"updater": {"active": true, "dangerousInsecureTransportProtocol": true}}',
}).length;

console.log(`rust bench: ${commands.length} commands, ${boundaries.length} unsafe/ffi boundaries, tauri=${tauriObs}`);
if (commands.length < 3) process.exit(1);
if (boundaries.length < 2) process.exit(1);
if (tauriObs < 1) process.exit(1);
console.log('GATE: PASS');
