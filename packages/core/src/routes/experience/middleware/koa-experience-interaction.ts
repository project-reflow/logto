import type { MiddlewareType } from 'koa';
import { type IRouterParamContext } from 'koa-router';

import type TenantContext from '#src/tenants/TenantContext.js';

import ExperienceInteraction from '../classes/experience-interaction.js';
import { experienceRoutes } from '../const.js';
import { type WithHooksAndLogsContext } from '../types.js';

export type WithExperienceInteractionContext<
  ContextT extends IRouterParamContext = IRouterParamContext,
> = ContextT & {
  experienceInteraction: ExperienceInteraction;
};

/**
 * White-listed endpoints that does not require an validation and initialization of `ExperienceInteraction`.
 */
const whiteListedEndpoint = [
  // PUT /experience:  New ExperienceInteraction instance supposed to be created for this request.
  {
    method: 'PUT',
    path: `${experienceRoutes.prefix}`,
  },
  // GET /experience/sso-connectors:  Fetch available SSO connectors for a given email, no interaction needed.
  {
    method: 'GET',
    path: `${experienceRoutes.prefix}/sso-connectors`,
  },
  // POST /experience/preflight/sign-in-passkey/authentication:  Generate WebAuthn authentication options for passkey sign-in, no interaction needed.
  {
    method: 'POST',
    path: `${experienceRoutes.prefix}/preflight/sign-in-passkey/authentication`,
  },
];

/**
 * @overview This middleware initializes the `ExperienceInteraction` for the current request.
 * The `ExperienceInteraction` instance is used to manage all the data related to the current interaction.
 * All the interaction data is stored using oidc-provider's interaction session.
 *
 * @see {@link https://github.com/panva/node-oidc-provider/blob/main/docs/README.md#user-flows}
 */
export default function koaExperienceInteraction<
  StateT,
  ContextT extends WithHooksAndLogsContext,
  ResponseT,
>(
  tenant: TenantContext
): MiddlewareType<StateT, WithExperienceInteractionContext<ContextT>, ResponseT> {
  return async (ctx, next) => {
    const {
      interactionDetails,
      request: { method, path },
    } = ctx;

    // Skip initializing `ExperienceInteraction` for white-listed endpoints.
    if (
      whiteListedEndpoint.some((endpoint) => endpoint.method === method && endpoint.path === path)
    ) {
      return next();
    }

    ctx.experienceInteraction = new ExperienceInteraction(ctx, tenant, interactionDetails);

    try {
      await next();

      // Name the identified user on the entries of a successful step too, such as an MFA
      // verification, so the audit trail can tie each step to a person. A user id that the
      // route set itself wins, because `prependAllLogEntries` puts this value first.
      const { identifiedUserId } = ctx.experienceInteraction;

      if (identifiedUserId) {
        ctx.prependAllLogEntries({ userId: identifiedUserId });
      }
    } catch (error) {
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- make sure the interaction is initialized
      if (ctx.experienceInteraction) {
        ctx.prependAllLogEntries({
          interaction: ctx.experienceInteraction.toJson(),
          userId: ctx.experienceInteraction.identifiedUserId,
        });
      }

      throw error;
    }
  };
}
