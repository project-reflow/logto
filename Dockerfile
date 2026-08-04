# syntax=docker/dockerfile:1.7

###### [STAGE] Build ######
FROM node:22-alpine AS builder
WORKDIR /etc/logto
ENV CI=true

# No need for Docker build
ENV PUPPETEER_SKIP_DOWNLOAD=true

### Install toolchain ###
RUN npm add --location=global pnpm@^10.0.0
# https://github.com/nodejs/docker-node/blob/main/docs/BestPractices.md#node-gyp-alpine
RUN apk add --no-cache python3 make g++ rsync

COPY . .

### Install dependencies and build ###
# Reuse the pnpm store between BuildKit runs to reduce duplicate downloads/writes.
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store pnpm i

### Set if dev features enabled ###
ARG dev_features_enabled
ENV DEV_FEATURES_ENABLED=${dev_features_enabled}

ARG applicationinsights_connection_string
ENV APPLICATIONINSIGHTS_CONNECTION_STRING=${applicationinsights_connection_string}

ARG logto_oss_survey_endpoint=
ENV LOGTO_OSS_SURVEY_ENDPOINT=${logto_oss_survey_endpoint}

# Raise Node's heap ceiling for the build: the console vite bundle peaks above
# the ~2 GB default old-space limit and OOMs the builder without this.
RUN NODE_OPTIONS=--max-old-space-size=4096 pnpm -r build

### Add official connectors ###
ARG additional_connector_args
ENV ADDITIONAL_CONNECTOR_ARGS=${additional_connector_args}
RUN pnpm cli connector link $ADDITIONAL_CONNECTOR_ARGS -p .

### Prune dependencies for production ###
# Keep prune + production install in one layer to avoid extra transient disk usage.
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
  rm -rf node_modules packages/**/node_modules && NODE_ENV=production pnpm i

### Clean up ###
RUN rm -rf .scripts pnpm-*.yaml packages/cloud

###### [STAGE] Seal ######
FROM node:22-alpine AS app
WORKDIR /etc/logto

# Security: patch known base-image and bundled-tool vulnerabilities.
# - Upgrade OpenSSL/libcrypto3/libssl3 to the latest Alpine patch (clears CVE-2026-34182/-45447
#   /-7383/-9076/-34180/-34181/-34183/-42764/-42766/-42767/-42769/-45445/-45446/-42768/-42770).
# - Refresh the globally-bundled npm so its vendored picomatch reaches >=4.0.4 (CVE-2026-33671).
# - Drop npm's vendored undici (only pulled in by node-gyp for build-time native-module
#   downloads, never exercised by the runtime `npm run start`). npm bundles undici 6.x, which
#   can't reach the 7.x fixes, so removal clears CVE-2026-12151 and related advisories.
# - Replace npm's vendored brace-expansion and ip-address with patched releases. npm@latest
#   still ships brace-expansion 5.0.7 (CVE-2026-69152, CVE-2026-14257) and ip-address 10.2.0
#   (CVE-2026-69192), so refreshing npm alone does not clear them. Both are drop-in: the
#   replacements are semver patch/minor, ip-address has no dependencies, and brace-expansion
#   5.0.9 needs balanced-match ^4.0.2, which npm already bundles. `npm install --prefix` is not
#   usable here because it re-resolves npm's own manifest, which references unpublished
#   internal packages, so unpack the tarballs over the vendored directories instead.
RUN apk --no-cache upgrade openssl libcrypto3 libssl3 \
  && npm install -g npm@latest \
  && for spec in brace-expansion@5.0.9 ip-address@10.3.1; do \
       name="${spec%@*}"; \
       npm pack "$spec" --pack-destination /tmp >/dev/null \
       && tar -xzf /tmp/"$name"-*.tgz -C /tmp \
       && rm -rf "/usr/local/lib/node_modules/npm/node_modules/$name" \
       && mv /tmp/package "/usr/local/lib/node_modules/npm/node_modules/$name" \
       || exit 1; \
     done \
  && rm -f /tmp/*.tgz \
  && rm -rf /usr/local/lib/node_modules/npm/node_modules/undici \
  && npm cache clean --force

ARG logto_oss_survey_endpoint=
ARG private_key_rotation_grace_period=0
# Default to empty so external survey relaying stays opt-in for controlled builds/environments.
ENV LOGTO_OSS_SURVEY_ENDPOINT=${logto_oss_survey_endpoint}
ENV PRIVATE_KEY_ROTATION_GRACE_PERIOD=${private_key_rotation_grace_period}
COPY --from=builder /etc/logto .
RUN mkdir -p /etc/logto/packages/cli/alteration-scripts && chmod g+w /etc/logto/packages/cli/alteration-scripts
EXPOSE 3001
ENTRYPOINT ["npm", "run"]
CMD ["start"]
