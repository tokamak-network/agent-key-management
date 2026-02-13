/**
 * Marker types for TEE trust boundaries.
 * These are compile-time markers that help developers understand
 * which data lives inside vs outside the TEE.
 */

/** Data that must remain inside the TEE boundary */
export type TeeConfidential<T> = T & { readonly __tee: 'confidential' };

/** Data that can safely cross the TEE boundary */
export type TeePublic<T> = T & { readonly __tee: 'public' };

/** Mark data as TEE-confidential (identity function, compile-time only) */
export function markConfidential<T>(value: T): TeeConfidential<T> {
  return value as TeeConfidential<T>;
}

/** Mark data as TEE-public (identity function, compile-time only) */
export function markPublic<T>(value: T): TeePublic<T> {
  return value as TeePublic<T>;
}
