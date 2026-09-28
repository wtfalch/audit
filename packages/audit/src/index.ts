/**
 * `ledgerReadHandler`, `fetchLedgerPage`/`fetchMergedLedgerPage` and their
 * types live at `@wtfalch/audit/read` (`./read/index.ts`), not here: `read.ts`
 * imports `@wtfalch/contracts` at the top level, and `@wtfalch/contracts` is
 * an optional peer (ADR 0001) -- a host that never mounts `ledgerReadHandler`
 * must not need it installed just to import `createLedger` from this root
 * entry (audit#33).
 */
export type { ChainVerifyResult, SealedChain, SealInput } from './chain.js';
export { computeErasureHash, sealRow, verifyChain } from './chain.js';
export { auditPolicyModule, catalogue, type Permission } from './catalogue.js';
export * from './ledger.js';
export { assertRuntimeRole, UnsafeRuntimeRoleError } from './runtime-role-guard.js';
export { AUDIT_LIMITS, type AuditRow, isJsonValue, rowSchema } from './schema.js';
export type { CefOptions } from './siem.js';
export { toCef, toCefLines } from './siem.js';
export * from './tables.js';
export * from './vocabulary.js';
