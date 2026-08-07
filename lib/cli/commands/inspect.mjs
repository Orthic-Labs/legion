import { inspectProduct } from '../../core/inspect-product.mjs';
export async function runInspect(args, { stdout, cwd }) { const result = await inspectProduct({ root: cwd, projection: { files: [] } }, { clock: { now: () => new Date(0) } }); stdout.write(`${JSON.stringify(result)}\n`); return { exitCode: result.portfolio.coverage.unknownDeliverables.length ? 2 : 0 }; }
