import { LogResult } from '@logto/schemas';

import {
  anonymousActorId,
  shouldWriteAuditLine,
  toAuditLine,
  writeAuditLine,
} from './audit-stdout.js';

const { jest } = import.meta;

const occurredAt = new Date('2026-01-02T03:04:05.000Z');

// The SHA-256 of 'session-1'.
const sessionOneSha256 = '84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b';

describe('shouldWriteAuditLine', () => {
  it.each([
    ['Interaction.SignIn.Submit', LogResult.Success, true],
    ['Interaction.SignIn.Verification.Password.Submit', LogResult.Error, true],
    ['Interaction.SignIn.Verification.Totp.Submit', LogResult.Success, true],
    ['RevokeToken', LogResult.Success, true],
    ['TrustedDevice.Created', LogResult.Success, true],
    ['ExchangeTokenBy.RefreshToken', LogResult.Success, false],
    ['ExchangeTokenBy.RefreshToken', LogResult.Error, true],
    ['ExchangeTokenBy.AuthorizationCode', LogResult.Success, false],
    ['ExchangeTokenBy.DeviceCode', LogResult.Success, false],
    ['ExchangeTokenBy.ClientCredentials', LogResult.Success, true],
    ['ExchangeTokenBy.TokenExchange', LogResult.Success, true],
    ['ExchangeTokenBy.TokenExchange', LogResult.Error, true],
    ['TriggerHook.PostSignIn', LogResult.Success, false],
    ['TriggerHook.PostSignIn', LogResult.Error, false],
  ])('%s with result %s → %s', (key, result, expected) => {
    expect(shouldWriteAuditLine(key, result)).toBe(expected);
  });
});

describe('toAuditLine', () => {
  it('maps a successful sign-in to a user action', () => {
    expect(
      toAuditLine(
        'log-1',
        {
          key: 'Interaction.SignIn.Submit',
          result: LogResult.Success,
          userId: 'user-1',
          applicationId: 'app-1',
          sessionId: 'session-1',
          ip: '203.0.113.7',
        },
        occurredAt
      )
    ).toEqual({
      log_type: 'audit',
      occurred_at: '2026-01-02T03:04:05.000Z',
      action: 'logto.Interaction.SignIn.Submit',
      actor_type: 'user',
      actor_id: 'user-1',
      actor_client_id: 'app-1',
      on_behalf_of: null,
      actor_user_type: null,
      resource_type: 'user',
      resource_id: 'user-1',
      organization_id: null,
      project_id: null,
      correlation_id: null,
      client_ip: '203.0.113.7',
      metadata: { log_id: 'log-1', result: 'Success', session_id_sha256: sessionOneSha256 },
    });
  });

  it('writes the anonymous actor and the error code for a failed sign-in with no user', () => {
    const line = toAuditLine(
      'log-2',
      {
        key: 'Interaction.SignIn.Verification.Password.Submit',
        result: LogResult.Error,
        error: { code: 'session.invalid_credentials', message: 'Wrong credentials.' },
        payload: { identifier: { type: 'email', value: 'person@example.com' }, password: '******' },
      },
      occurredAt
    );

    expect(line.actor_id).toBe(anonymousActorId);
    expect(line.resource_id).toBe(anonymousActorId);
    expect(line.client_ip).toBeNull();
    expect(line.metadata).toEqual({
      log_id: 'log-2',
      result: 'Error',
      error_code: 'session.invalid_credentials',
    });
  });

  it('never copies an identifier, a user agent, a profile, or an error message', () => {
    const serialized = JSON.stringify(
      toAuditLine(
        'log-3',
        {
          key: 'Interaction.Register.Submit',
          result: LogResult.Error,
          userId: 'user-3',
          error: { code: 'user.email_already_in_use', message: 'person@example.com is taken' },
          userAgent: 'secret-agent/1.0',
          email: 'person@example.com',
          interaction: { profile: { primaryPhone: '+15550100', name: 'Private Name' } },
          payload: { identifier: { type: 'email', value: 'person@example.com' } },
        },
        occurredAt
      )
    );

    expect(serialized).not.toContain('person@example.com');
    expect(serialized).not.toContain('secret-agent');
    expect(serialized).not.toContain('+15550100');
    expect(serialized).not.toContain('Private Name');
  });

  it('reads the connector id and the verification id from the nested payload of an SSO entry', () => {
    const line = toAuditLine(
      'log-4',
      {
        key: 'Interaction.SignIn.Verification.EnterpriseSso.Submit',
        result: LogResult.Success,
        payload: { connectorId: 'sso-1', verificationId: 'verification-1', connectorData: {} },
      },
      occurredAt
    );

    expect(line.metadata).toMatchObject({
      connector_id: 'sso-1',
      verification_id: 'verification-1',
    });
  });

  it('maps a client credentials failure to a service action on the application', () => {
    const line = toAuditLine(
      'log-5',
      {
        key: 'ExchangeTokenBy.ClientCredentials',
        result: LogResult.Error,
        applicationId: 'm2m-1',
        error: { code: 'oidc.invalid_client' },
      },
      occurredAt
    );

    expect(line).toMatchObject({
      action: 'logto.ExchangeTokenBy.ClientCredentials',
      actor_type: 'service',
      actor_id: 'm2m-1',
      actor_client_id: 'm2m-1',
      resource_type: 'application',
      resource_id: 'm2m-1',
    });
  });

  it('reads the OAuth error code of an OIDC error that is stored as a JSON string', () => {
    const line = toAuditLine(
      'log-10',
      {
        key: 'ExchangeTokenBy.RefreshToken',
        result: LogResult.Error,
        applicationId: 'app-1',
        error: JSON.stringify({
          name: 'InvalidGrant',
          error: 'invalid_grant',
          error_detail: 'refresh token not found',
          stack: 'InvalidGrant: invalid_grant\n    at private/path.js:1:1',
        }),
      },
      occurredAt
    );

    expect(line.metadata.error_code).toBe('invalid_grant');
    expect(JSON.stringify(line)).not.toContain('private/path');
  });

  it('writes no error code for an error string that is not JSON', () => {
    const line = toAuditLine(
      'log-11',
      { key: 'Interaction.SignIn.Submit', result: LogResult.Error, error: 'plain text failure' },
      occurredAt
    );

    expect(line.metadata).not.toHaveProperty('error_code');
  });

  it('maps a JWT customizer run for client credentials to a service action', () => {
    const line = toAuditLine(
      'log-12',
      { key: 'JwtCustomizer.ClientCredentials', result: LogResult.Error, applicationId: 'm2m-2' },
      occurredAt
    );

    expect(line).toMatchObject({ actor_type: 'service', actor_id: 'm2m-2' });
  });

  it('maps a token exchange to an agent action: the person acts through the client', () => {
    const line = toAuditLine(
      'log-15',
      {
        key: 'ExchangeTokenBy.TokenExchange',
        result: LogResult.Success,
        userId: 'user-15',
        applicationId: 'agents-client',
      },
      occurredAt
    );

    expect(line).toMatchObject({
      actor_type: 'agent',
      actor_id: 'user-15',
      actor_client_id: 'agents-client',
      resource_type: 'user',
      resource_id: 'user-15',
    });
  });

  it('names the client id the caller sent when Logto has not resolved the client', () => {
    const line = toAuditLine(
      'log-13',
      {
        key: 'ExchangeTokenBy.ClientCredentials',
        result: LogResult.Error,
        error: { code: 'oidc.invalid_client' },
        params: { client_id: 'm2m-unknown', client_secret: '******' },
      },
      occurredAt
    );

    expect(line).toMatchObject({ actor_id: 'm2m-unknown', actor_client_id: 'm2m-unknown' });
    expect(JSON.stringify(line)).not.toContain('client_secret');
  });

  it('keeps a CIMD client id of the full column width, and cuts a longer one there', () => {
    const fullWidth = `https://client.example/${'a'.repeat(2048 - 23)}`;
    const keep = toAuditLine(
      'log-16',
      { key: 'Interaction.SignIn.Submit', result: LogResult.Success, cimdClientId: fullWidth },
      occurredAt
    );
    const cut = toAuditLine(
      'log-17',
      {
        key: 'ExchangeTokenBy.ClientCredentials',
        result: LogResult.Error,
        params: { client_id: `${fullWidth}-and-more` },
      },
      occurredAt
    );

    expect(keep.actor_client_id).toBe(fullWidth);
    expect(cut.actor_client_id).toBe(fullWidth);
  });

  it('names a CIMD client when the entry has no registered application', () => {
    const line = toAuditLine(
      'log-14',
      {
        key: 'Interaction.SignIn.Submit',
        result: LogResult.Success,
        userId: 'user-14',
        cimdClientId: 'https://client.example/metadata.json',
      },
      occurredAt
    );

    expect(line.actor_client_id).toBe('https://client.example/metadata.json');
  });

  it('caps each metadata string at 256 characters', () => {
    const line = toAuditLine(
      'log-6',
      {
        key: 'Interaction.SignIn.Submit',
        result: LogResult.Success,
        connectorId: 'x'.repeat(1000),
      },
      occurredAt
    );

    expect(line.metadata.connector_id).toHaveLength(256);
  });
});

describe('writeAuditLine', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('writes one JSON line for an entry that passes the filter', () => {
    const write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);

    writeAuditLine(
      'log-7',
      { key: 'Interaction.SignIn.Submit', result: LogResult.Success, userId: 'user-7' },
      occurredAt
    );

    expect(write).toHaveBeenCalledTimes(1);
    const [written] = write.mock.calls[0] ?? [];
    expect(typeof written).toBe('string');
    expect(String(written).endsWith('\n')).toBe(true);
    expect(JSON.parse(String(written))).toMatchObject({
      log_type: 'audit',
      action: 'logto.Interaction.SignIn.Submit',
      actor_id: 'user-7',
    });
  });

  it('writes nothing for a successful token exchange', () => {
    const write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);

    writeAuditLine(
      'log-8',
      { key: 'ExchangeTokenBy.RefreshToken', result: LogResult.Success, userId: 'user-8' },
      occurredAt
    );

    expect(write).not.toHaveBeenCalled();
  });

  it('does not throw when the write fails, and names the key only', () => {
    jest.spyOn(process.stdout, 'write').mockImplementation(() => {
      throw new Error('EPIPE');
    });
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    const error = jest.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => {
      writeAuditLine(
        'log-9',
        { key: 'Interaction.SignIn.Submit', result: LogResult.Success, userId: 'user-9' },
        occurredAt
      );
    }).not.toThrow();
    expect(error).toHaveBeenCalledTimes(1);
    const logged = JSON.stringify(error.mock.calls[0]);
    expect(logged).toContain('stdout write failed for log key Interaction.SignIn.Submit');
    expect(logged).not.toContain('user-9');
  });
});
