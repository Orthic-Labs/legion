import { KernelError } from './errors.mjs';

export function schedulerOptionsFromArgv(argv = process.argv.slice(2)) {
  return { serial: argv.includes('--serial') };
}

export class LaneScheduler {
  constructor({ serial = false } = {}) {
    this.serial = serial;
  }

  async execute(nodes) {
    const byId = new Map();
    for (const node of nodes) {
      if (!node?.id || typeof node.run !== 'function') {
        throw new KernelError('INVALID_ARGUMENT', 'scheduler node requires id and run function', { category: 'usage' });
      }
      if (byId.has(node.id)) throw new KernelError('SCOPE_CONFLICT', `duplicate lane id: ${node.id}`, { category: 'conflict' });
      byId.set(node.id, { ...node, dependencies: node.dependencies ?? [] });
    }
    for (const node of byId.values()) {
      for (const dependency of node.dependencies) {
        if (!byId.has(dependency)) {
          throw new KernelError('INVALID_ARGUMENT', `unknown dependency ${dependency} for ${node.id}`, { category: 'usage' });
        }
      }
    }

    const pending = new Set(byId.keys());
    const results = new Map();
    const locks = new Map();
    const executeNode = async (node) => {
      const invoke = () => node.run({ results: new Map(results), nodeId: node.id });
      if (!node.concurrencyKey || this.serial) return invoke();
      const prior = locks.get(node.concurrencyKey) ?? Promise.resolve();
      const current = prior.then(invoke, invoke);
      locks.set(node.concurrencyKey, current.catch(() => undefined));
      return current;
    };

    while (pending.size) {
      const ready = [...pending].map((id) => byId.get(id)).filter((node) => node.dependencies.every((id) => results.has(id)));
      if (!ready.length) {
        throw new KernelError('PLAN_BINDING_DRIFT', 'dependency graph contains a cycle', { category: 'precondition' });
      }
      const batch = this.serial ? ready.slice(0, 1) : ready;
      const values = await Promise.all(batch.map(async (node) => [node.id, await executeNode(node)]));
      for (const [id, value] of values) {
        results.set(id, value);
        pending.delete(id);
      }
    }
    return new Map(nodes.map(({ id }) => [id, results.get(id)]));
  }
}
