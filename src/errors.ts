/**
 * An expected failure with the HTTP status to answer with. The error handler
 * sends its `message` to the client as-is, so keep it user-facing (Indonesian).
 */
export class AppError extends Error {
  readonly code: number;

  constructor(code: number, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "AppError";
    this.code = code;
  }
}
