export const RUN_DIRECTORIES = Object.freeze(['plan', 'inventory/product-portfolio', 'inventory/components', 'inventory/stacks', 'inventory/external-systems', 'controls', 'scenarios', 'facts', 'provider-results', 'raw-outputs', 'reports', 'verification', 'remediation']);

export function runLayout(root) {
  return Object.freeze({ root, directories: RUN_DIRECTORIES.map((path) => ({ path })) });
}
