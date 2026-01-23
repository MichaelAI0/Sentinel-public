/**
 * Result Type for Error Handling
 *
 * Provides a functional approach to error handling without exceptions:
 * - Result<T, E> = Ok<T> | Err<E>
 * - Type-safe error propagation
 * - Chainable transformations
 *
 * @module types/result
 *
 * @todo Phase 3: Add async Result variants (ResultAsync)
 * @todo Phase 4: Add Result combinators (combine, sequence)
 */

/**
 * Success result containing a value
 */
export type Ok<T> = {
  readonly ok: true;
  readonly value: T;
};

/**
 * Failure result containing an error
 */
export type Err<E> = {
  readonly ok: false;
  readonly error: E;
};

/**
 * Result type - either success with value or failure with error
 */
export type Result<T, E = Error> = Ok<T> | Err<E>;

/**
 * Create a success result
 */
export function ok<T>(value: T): Ok<T> {
  return { ok: true, value };
}

/**
 * Create a failure result
 */
export function err<E>(error: E): Err<E> {
  return { ok: false, error };
}

/**
 * Type guard for success result
 */
export function isOk<T, E>(result: Result<T, E>): result is Ok<T> {
  return result.ok === true;
}

/**
 * Type guard for failure result
 */
export function isErr<T, E>(result: Result<T, E>): result is Err<E> {
  return result.ok === false;
}

/**
 * Unwrap a result, throwing if it's an error
 */
export function unwrap<T, E>(result: Result<T, E>): T {
  if (isOk(result)) {
    return result.value;
  }
  throw result.error;
}

/**
 * Unwrap a result, returning a default value if it's an error
 */
export function unwrapOr<T, E>(result: Result<T, E>, defaultValue: T): T {
  if (isOk(result)) {
    return result.value;
  }
  return defaultValue;
}

/**
 * Unwrap a result, computing a default value if it's an error
 */
export function unwrapOrElse<T, E>(result: Result<T, E>, fn: (error: E) => T): T {
  if (isOk(result)) {
    return result.value;
  }
  return fn(result.error);
}

/**
 * Map over a success value
 */
export function map<T, U, E>(result: Result<T, E>, fn: (value: T) => U): Result<U, E> {
  if (isOk(result)) {
    return ok(fn(result.value));
  }
  return result;
}

/**
 * Map over an error value
 */
export function mapErr<T, E, F>(result: Result<T, E>, fn: (error: E) => F): Result<T, F> {
  if (isErr(result)) {
    return err(fn(result.error));
  }
  return result;
}

/**
 * Chain Result-returning operations (flatMap)
 */
export function andThen<T, U, E>(
  result: Result<T, E>,
  fn: (value: T) => Result<U, E>,
): Result<U, E> {
  if (isOk(result)) {
    return fn(result.value);
  }
  return result;
}

/**
 * Provide an alternative Result if this one is an error
 */
export function orElse<T, E, F>(
  result: Result<T, E>,
  fn: (error: E) => Result<T, F>,
): Result<T, F> {
  if (isErr(result)) {
    return fn(result.error);
  }
  return result;
}

/**
 * Execute a side effect on success
 */
export function tap<T, E>(result: Result<T, E>, fn: (value: T) => void): Result<T, E> {
  if (isOk(result)) {
    fn(result.value);
  }
  return result;
}

/**
 * Execute a side effect on error
 */
export function tapErr<T, E>(result: Result<T, E>, fn: (error: E) => void): Result<T, E> {
  if (isErr(result)) {
    fn(result.error);
  }
  return result;
}

/**
 * Convert a Promise to a Result
 */
export async function fromPromise<T, E = Error>(
  promise: Promise<T>,
  mapError?: (error: unknown) => E,
): Promise<Result<T, E>> {
  try {
    const value = await promise;
    return ok(value);
  } catch (error) {
    if (mapError) {
      return err(mapError(error));
    }
    return err(error as E);
  }
}

/**
 * Convert a sync function to a Result
 */
export function tryCatch<T, E = Error>(
  fn: () => T,
  mapError?: (error: unknown) => E,
): Result<T, E> {
  try {
    return ok(fn());
  } catch (error) {
    if (mapError) {
      return err(mapError(error));
    }
    return err(error as E);
  }
}

/**
 * Combine multiple Results into a single Result
 * If any Result is an error, returns the first error
 */
export function all<T, E>(results: Result<T, E>[]): Result<T[], E> {
  const values: T[] = [];

  for (const result of results) {
    if (isErr(result)) {
      return result;
    }
    values.push(result.value);
  }

  return ok(values);
}

/**
 * Combine multiple Results into a single Result
 * Collects all errors if any fail
 */
export function allSettled<T, E>(results: Result<T, E>[]): Result<T[], E[]> {
  const values: T[] = [];
  const errors: E[] = [];

  for (const result of results) {
    if (isOk(result)) {
      values.push(result.value);
    } else {
      errors.push(result.error);
    }
  }

  if (errors.length > 0) {
    return err(errors);
  }

  return ok(values);
}

/**
 * Match on a Result (pattern matching style)
 */
export function match<T, E, R>(
  result: Result<T, E>,
  handlers: {
    ok: (value: T) => R;
    err: (error: E) => R;
  },
): R {
  if (isOk(result)) {
    return handlers.ok(result.value);
  }
  return handlers.err(result.error);
}

/**
 * Type-safe async Result wrapper for functions
 */
export type AsyncResult<T, E = Error> = Promise<Result<T, E>>;

/**
 * Helper to create async Result-returning functions
 */
export function asyncResult<T, A extends unknown[], E = Error>(
  fn: (...args: A) => Promise<T>,
  mapError?: (error: unknown) => E,
): (...args: A) => AsyncResult<T, E> {
  return async (...args: A) => {
    return fromPromise(fn(...args), mapError);
  };
}
