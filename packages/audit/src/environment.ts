/** Where a ledger runs. A stage database is a copy of production's, so stage never seals or anchors. */
export type AuditEnvironment = 'stage' | 'production';

/**
 * Reads the host's `APP_ENVIRONMENT` value. Throws on anything but `stage` or
 * `production`, so a typo cannot silently turn sealing on in a copy.
 */
export function parseEnvironment(value: string | undefined): AuditEnvironment {
  if (value === 'stage' || value === 'production') return value;
  throw new Error(`audit: APP_ENVIRONMENT must be "stage" or "production", got ${String(value)}`);
}

/** Throws in stage; `action` names what was refused. */
export function assertProduction(environment: AuditEnvironment | undefined, action: string): void {
  if (environment === 'stage') {
    throw new Error(
      `audit: ${action} is refused in stage: a stage copy must not use production's key or anchor outside`,
    );
  }
  if (environment !== undefined && environment !== 'production') {
    throw new Error('audit: environment must be "stage" or "production"');
  }
}
