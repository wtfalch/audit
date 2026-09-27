/** `execute()`'s rows: postgres-js returns an array, PGlite an object holding one. */
export function resultRows<T>(result: unknown): T[] {
  return Array.isArray(result) ? (result as T[]) : ((result as { rows?: T[] }).rows ?? []);
}
