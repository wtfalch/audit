/**
 * `@wtfalch/audit/read`: the cross-app read handler and its client, on
 * `@wtfalch/contracts` (ADR 0001). Split out of the root entry so a host
 * that only writes to the ledger -- never mounts `ledgerReadHandler` or
 * calls `fetchMergedLedgerPage` -- never needs `@wtfalch/contracts`
 * installed just to import `@wtfalch/audit` (audit#33). The same shape as
 * `@wtfalch/audit/react` for `@wtfalch/design`/`react`/`react-dom`.
 */
export {
  fetchLedgerPage,
  fetchMergedLedgerPage,
  LedgerReadError,
  type FetchLedgerPageOptions,
  type FetchMergedLedgerPageOptions,
  type LedgerSource,
  type MergedLedgerPage,
  type MergedLedgerRow,
} from '../client.js';
export {
  ledgerReadHandler,
  type Authorize,
  type AuthorizedRead,
  type LedgerReadHandlerOptions,
  type LedgerReadPage,
  type LedgerReadRow,
} from '../read.js';
