/**
 * An expected failure with the HTTP status to answer with. The error handler
 * sends its `message` to the client as-is, so keep it user-facing (Indonesian).
 */
export class AppError extends Error {
  readonly code: number;
  /** Sent as the envelope's `data` (e.g. `{ reason }`); null when absent. */
  readonly data?: unknown;

  constructor(code: number, message: string, options?: { cause?: unknown; data?: unknown }) {
    super(message, { cause: options?.cause });
    this.name = "AppError";
    this.code = code;
    this.data = options?.data;
  }
}
