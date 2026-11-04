/**
 * Writes each audit log entry to stdout as one structured JSON line, in addition to the
 * `logs` table. A log shipper (CloudWatch, Cloud Logging, or a SIEM agent) can then collect
 * sign-in events with the other application logs, without database access.
 *
 * The line carries ids and short descriptors only. The mapper picks named fields from the
 * payload, and never copies the payload itself, so an identifier the user typed (an email or a
 * phone number), a user agent, or a profile never reaches the line. The `log_id` field joins
 * the line to its row in the `logs` table, where those details stay.
 *
 * The line is written before the row is inserted, so a failed insert does not lose it. Two
 * results follow: a line can name a `log_id` with no row, and an entry with an idempotency key
 * writes one line per retry for its one row. A reader can dedupe on `log_id`.
 */
import { createHash } from 'node:crypto';

import type { LogContextPayload } from '@logto/schemas';
import { LogResult, hook, jwtCustomizer, token } from '@logto/schemas';
import { ConsoleLog } from '@logto/shared';
import { removeUndefinedKeys } from '@silverhand/essentials';
import chalk from 'chalk';

import { safeParseJson } from '#src/utils/json.js';
import { isRecord } from '#src/utils/sensitive-data.js';

const auditConsole = new ConsoleLog(chalk.yellow('audit'));

/** The longest string a metadata value may hold. */
const metadataStringMaxLength = 256;

/**
 * The longest id the line holds. A CIMD client id can be as long as its `varchar(2048)`
 * column, and a cut id could match another client. The bound still keeps a `client_id` that a
 * caller sends from making the line too long.
 */
const idMaxLength = 2048;

/** The actor id when the entry names no user, such as a sign-in with an unknown identifier. */
export const anonymousActorId = 'anonymous';

/* eslint-disable @typescript-eslint/ban-types -- Every field is on the line, with `null` when empty, so a log query never has to tell an empty field from a missing one. */
type AuditLine = {
  log_type: 'audit';
  occurred_at: string;
  action: string;
  actor_type: 'user' | 'agent' | 'service';
  actor_id: string;
  actor_client_id: string | null;
  on_behalf_of: null;
  actor_user_type: null;
  resource_type: 'user' | 'application';
  resource_id: string;
  organization_id: null;
  project_id: null;
  correlation_id: null;
  client_ip: string | null;
  metadata: Record<string, string>;
};
/* eslint-enable @typescript-eslint/ban-types */

// Built from the schema enums, so an upstream rename fails the build instead of changing the
// filter in silence.
const tokenExchangePrefix = `${token.Type.ExchangeTokenBy}.`;
const jwtCustomizerPrefix = `${jwtCustomizer.prefix}.`;
const webhookPrefix = `${hook.Type.TriggerHook}.`;
/** The key of a client credentials grant: a machine acting on its own credentials. */
const clientCredentialsGrantKey = `${token.Type.ExchangeTokenBy}.${token.ExchangeByType.ClientCredentials}`;
/** The keys of a client credentials grant and of its JWT customizer run. */
const clientCredentialsKeys = new Set<string>([
  clientCredentialsGrantKey,
  `${jwtCustomizerPrefix}${jwtCustomizer.Type.ClientCredentials}`,
]);
/**
 * The key of a token exchange (RFC 8693): a service gets a delegated token to act for a person.
 * The line calls a client that acts for a person an `agent`: the person is the actor, and the
 * client is `actor_client_id`.
 */
const tokenExchangeKey = `${token.Type.ExchangeTokenBy}.${token.ExchangeByType.TokenExchange}`;

/**
 * The token grants that are written when they succeed. A machine client that gets a token on
 * its own credentials, and a token exchange that mints a delegated token for a person, are
 * actions to audit. The other grants (authorization code, refresh token, device code) come with
 * each sign-in or token refresh, so only a failure of one of them is written.
 */
const auditedSuccessfulGrantKeys = new Set<string>([clientCredentialsGrantKey, tokenExchangeKey]);

/** Whether an entry goes to stdout. Webhook delivery entries are not user actions. */
export const shouldWriteAuditLine = (key: string, result: LogResult): boolean => {
  if (key.startsWith(webhookPrefix)) {
    return false;
  }

  if (key.startsWith(tokenExchangePrefix)) {
    return result === LogResult.Error || auditedSuccessfulGrantKeys.has(key);
  }

  // A JWT customizer runs on each token that Logto issues, also on a refresh. So only a failed
  // run is written. The grant entry of the same request records a successful grant.
  if (key.startsWith(jwtCustomizerPrefix)) {
    return result === LogResult.Error;
  }

  return true;
};

const nonEmptyString = (value: unknown, maxLength: number): string | undefined =>
  typeof value === 'string' && value.length > 0 ? value.slice(0, maxLength) : undefined;

/** A short descriptor for `metadata`, such as an error code. */
const asString = (value: unknown): string | undefined =>
  nonEmptyString(value, metadataStringMaxLength);

/** An id: a user, a client, an address, or a session. */
const asId = (value: unknown): string | undefined => nonEmptyString(value, idMaxLength);

/**
 * The error code of an entry. A `RequestError` stores a record with `code`. An OIDC provider
 * error is stored as a JSON string, with the OAuth error code (such as `invalid_grant`) in
 * `error`. The message, the description, and the stack are never read: they can hold input.
 */
const errorCode = (error: unknown): string | undefined => {
  const record = typeof error === 'string' ? safeParseJson(error) : error;

  if (!isRecord(record)) {
    return undefined;
  }

  return asString(record.code) ?? asString(record.error);
};

/** Read a field from the top level of the payload, or from its nested `payload` record. */
const topOrNested = (payload: LogContextPayload, field: string): string | undefined =>
  asString(payload[field]) ??
  (isRecord(payload.payload) ? asString(payload.payload[field]) : undefined);

/**
 * The client of the entry: a registered application, a CIMD client, or, when Logto has not
 * resolved the client yet (such as a failed client credentials grant), the `client_id` the
 * caller sent. A client id is not a secret.
 */
const clientId = (payload: LogContextPayload): string | undefined =>
  asId(payload.applicationId) ??
  asId(payload.cimdClientId) ??
  (isRecord(payload.params) ? asId(payload.params.client_id) : undefined);

/**
 * The OIDC session id is also the value of the session cookie. The cookie is signed, so the
 * id alone cannot replay a session. The line still carries only a hash of it, which joins the
 * lines of one session without putting the cookie value in a log sink.
 */
const hashSessionId = (sessionId: string | undefined): string | undefined =>
  sessionId && createHash('sha256').update(sessionId).digest('hex');

/** Map one log entry to the audit line. */
export const toAuditLine = (
  logId: string,
  payload: LogContextPayload,
  occurredAt: Date
): AuditLine => {
  const { key, result } = payload;
  const userId = asId(payload.userId);
  const client = clientId(payload);
  const isService = clientCredentialsKeys.has(key);
  const actorId = (isService ? client : userId) ?? anonymousActorId;
  const actorType = isService ? 'service' : key === tokenExchangeKey ? 'agent' : 'user';

  const metadata: Record<string, string | undefined> = {
    log_id: logId,
    result,
    error_code: errorCode(payload.error),
    session_id_sha256: hashSessionId(asId(payload.sessionId)),
    connector_id: topOrNested(payload, 'connectorId'),
    verification_id: topOrNested(payload, 'verificationId'),
  };

  return {
    log_type: 'audit',
    occurred_at: occurredAt.toISOString(),
    action: `logto.${key}`,
    actor_type: actorType,
    actor_id: actorId,
    actor_client_id: client ?? null,
    on_behalf_of: null,
    actor_user_type: null,
    resource_type: isService ? 'application' : 'user',
    resource_id: actorId,
    organization_id: null,
    project_id: null,
    correlation_id: null,
    client_ip: asId(payload.ip) ?? null,
    metadata: removeUndefinedKeys(metadata),
  };
};

/**
 * Write the audit line of one entry to stdout. Never throws: the action has already taken
 * effect, so a failed write must not fail the request. The error line names the key only.
 */
export const writeAuditLine = (
  logId: string,
  payload: LogContextPayload,
  occurredAt = new Date()
): void => {
  try {
    if (!shouldWriteAuditLine(payload.key, payload.result)) {
      return;
    }

    process.stdout.write(`${JSON.stringify(toAuditLine(logId, payload, occurredAt))}\n`);
  } catch {
    auditConsole.error(`stdout write failed for log key ${payload.key}`);
  }
};
