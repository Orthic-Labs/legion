import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const sha256=(bytes)=>`sha256:${createHash('sha256').update(bytes).digest('hex')}`;
export async function runRuntimeModule(provider, host, input={}) {
  const script=provider.runner?.script??provider.runner?.module;
  if(!script||!provider.runner?.moduleDigest)throw new TypeError('runtime runner requires sealed module path and digest');
  const packageRoot=resolve(input.packageRoot??resolve(import.meta.dirname,'../../..'));
  const modulePath=resolve(packageRoot,script);
  if(relative(packageRoot,modulePath).startsWith('..'))throw new TypeError('runtime module escapes package root');
  const bytes=await readFile(modulePath);if(sha256(bytes)!==provider.runner.moduleDigest)throw new TypeError(`runtime module digest mismatch: ${script}`);
  const module=await import(`${pathToFileURL(modulePath).href}?digest=${provider.runner.moduleDigest.slice(-16)}`);
  if(module.default?.id&&module.default.id!==provider.id)throw new TypeError(`runtime module provider mismatch: ${provider.id}`);
  const runner=provider.runner.kind==='renderer'?(module.render??module.default?.render):(module.analyze??module.default?.analyze);
  if(typeof runner!=='function')throw new TypeError(`runtime module exports no ${provider.runner.kind==='renderer'?'render':'analyze'} function`);
  const result=await runner({host,input,provider:provider.id});return{schemaVersion:1,provider:provider.id,status:result?.status??'unproven',complete:result?.complete===true,...result};
}
