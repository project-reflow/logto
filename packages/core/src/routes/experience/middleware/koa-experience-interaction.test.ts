import { createMockUtils, pickDefault } from '@logto/shared/esm';

import type TenantContext from '#src/tenants/TenantContext.js';
import { createContextWithRouteParameters } from '#src/utils/test-utils.js';

const { jest } = import.meta;
const { mockEsmDefault } = createMockUtils(jest);

const toJson = jest.fn(() => ({ interactionEvent: 'SignIn' }));
const mockExperienceInteraction = jest.fn(
  (): { identifiedUserId?: string; toJson: typeof toJson } => ({
    toJson,
  })
);

mockEsmDefault('../classes/experience-interaction.js', () => mockExperienceInteraction);

const koaExperienceInteraction = await pickDefault(import('./koa-experience-interaction.js'));

const tenant = {} as unknown as TenantContext;

const createContext = (identifiedUserId?: string) => {
  mockExperienceInteraction.mockReturnValueOnce({ identifiedUserId, toJson });
  const prependAllLogEntries = jest.fn();
  const ctx = {
    ...createContextWithRouteParameters({ url: '/experience/verification/totp/verify' }),
    interactionDetails: {},
    prependAllLogEntries,
  };

  return { ctx, prependAllLogEntries };
};

describe('koaExperienceInteraction log context', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should name the identified user on the log entries of a successful step', async () => {
    const { ctx, prependAllLogEntries } = createContext('user-1');

    // @ts-expect-error -- partial context for the middleware under test
    await koaExperienceInteraction(tenant)(ctx, jest.fn());

    expect(prependAllLogEntries).toHaveBeenCalledWith({ userId: 'user-1' });
  });

  it('should add nothing to a successful step before the user is identified', async () => {
    const { ctx, prependAllLogEntries } = createContext();

    // @ts-expect-error -- partial context for the middleware under test
    await koaExperienceInteraction(tenant)(ctx, jest.fn());

    expect(prependAllLogEntries).not.toHaveBeenCalled();
  });

  it('should keep adding the interaction and the user to the entries of a failed step', async () => {
    const { ctx, prependAllLogEntries } = createContext('user-2');
    const error = new Error('verification failed');

    await expect(
      // @ts-expect-error -- partial context for the middleware under test
      koaExperienceInteraction(tenant)(ctx, jest.fn().mockRejectedValue(error))
    ).rejects.toBe(error);

    expect(prependAllLogEntries).toHaveBeenCalledTimes(1);
    expect(prependAllLogEntries).toHaveBeenCalledWith({
      interaction: { interactionEvent: 'SignIn' },
      userId: 'user-2',
    });
  });
});
