/**
 * The audit ledger's React reader, on `@wtfalch/design`. A client component:
 * the design package is React Aria underneath, so a Server Component in the
 * app calls `ledger.page()` and passes the result in.
 */
export { SecurityLog } from './SecurityLog.js';
export type {
  SecurityLogActorFor,
  SecurityLogOutcomeFor,
  SecurityLogPage,
  SecurityLogProps,
} from './SecurityLog.js';
