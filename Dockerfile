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

# Cache-bust for the layer below. BuildKit folds a build arg into a layer's cache key only when
# the instruction actually reads it, so a bare ARG line would change nothing. Without this, the
# `apk upgrade` has no input that varies between builds: `--pull` only re-resolves the floating
# node:22-alpine tag, and when that digest has not moved the GHA cache serves the old upgrade
# layer and the OS patch silently never lands. Pass the image tag so every release rebuilds it.
ARG apk_cache_bust=

# Security: patch known base-image and bundled-tool vulnerabilities.
# - Upgrade OpenSSL/libcrypto3/libssl3 to the latest Alpine patch.
# - Refresh the globally-bundled npm, which carries its own vendored dependency tree.
# - Drop npm's vendored undici (only pulled in by node-gyp for build-time native-module
#   downloads, never exercised by the runtime `npm run start`). npm bundles undici 6.x, which
#   can't reach the 7.x fixes, so removal clears CVE-2026-12151 and related advisories.
# - Replace three of npm's vendored copies with patched releases. Refreshing npm does not clear
#   them: npm 12.0.2 still ships brace-expansion 5.0.7 (CVE-2026-69152, CVE-2026-14257),
#   ip-address 10.2.0 (CVE-2026-69192) and tar 7.5.19 (CVE-2026-73566, CVE-2026-59873). All
#   three are drop-in. ip-address has no dependencies. brace-expansion 5.0.9 needs
#   balanced-match ^4.0.2, which npm bundles at 4.0.4. tar 7.5.22 declares the same dependency
#   set as 7.5.19, and npm already bundles every one of them at a satisfying version (chownr
#   3.0.0, yallist 5.0.0, minipass 7.1.3, minizlib 3.1.0, @isaacs/fs-minipass 4.0.1); npm's own
#   manifest asks for tar ^7.5.19, so 7.5.22 stays inside its declared range. `npm install
#   --prefix` is not usable here because it re-resolves npm's own manifest, which references
#   unpublished internal packages, so unpack the tarballs over the vendored directories instead.
#   Keep tar last in the loop: `npm pack` uses npm's vendored tar, so replacing it before the
#   other packs would run the untested copy for the rest of the loop.
RUN echo "cache-bust: ${apk_cache_bust}" >/dev/null \
  && apk --no-cache upgrade openssl libcrypto3 libssl3 \
  && npm install -g npm@latest \
  && for spec in brace-expansion@5.0.9 ip-address@10.5.1 tar@7.5.22; do \
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
