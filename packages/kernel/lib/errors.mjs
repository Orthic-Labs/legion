export const EXIT_CODES = Object.freeze({
  usage: 2,
  precondition: 3,
  authority: 4,
  policy: 5,
  integrity: 6,
  context: 7,
  execution: 8,
  external: 9,
  resource: 10,
  conflict: 11,
  cancelled: 130,
  internal: 70,
});

export class KernelError extends Error {
  constructor(code, message, options = {}) {
    const category = options.category ?? 'internal';
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'KernelError';
    this.code = code;
    this.category = category;
    this.layer = options.layer ?? 'kernel';
    this.retryable = options.retryable ?? false;
    this.statePreserved = options.statePreserved ?? true;
    this.exitCode = EXIT_CODES[category] ?? EXIT_CODES.internal;
    this.remediation = options.remediation ?? null;
    this.details = options.details ?? null;
  }

  toJSON() {
    return {
      code: this.code,
      category: this.category,
      message: this.message,
      responsibleLayer: this.layer,
      retryable: this.retryable,
      statePreserved: this.statePreserved,
      exitCode: this.exitCode,
      remediation: this.remediation,
      details: this.details,
    };
  }
}
