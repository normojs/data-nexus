# Production static build of Data Nexus Admin (Nuxt generate + nginx).
# Build:
#   docker build -t data-nexus-ui \
#     --build-arg NUXT_PUBLIC_ADMIN_API_BASE=http://gateway:8082 \
#     -f Dockerfile .
# Run:
#   docker run --rm -p 8080:80 data-nexus-ui

FROM node:22-alpine AS build
WORKDIR /app

RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .

ARG NUXT_PUBLIC_ADMIN_API_BASE=http://127.0.0.1:8082
ARG NUXT_PUBLIC_ADMIN_PASSWORD=
ARG NUXT_PUBLIC_OIDC_ISSUER=
ARG NUXT_PUBLIC_OIDC_CLIENT_ID=
ARG NUXT_PUBLIC_OIDC_REDIRECT_URI=
ARG NUXT_PUBLIC_OIDC_SCOPES=openid profile email

ENV NUXT_PUBLIC_ADMIN_API_BASE=$NUXT_PUBLIC_ADMIN_API_BASE \
    NUXT_PUBLIC_ADMIN_PASSWORD=$NUXT_PUBLIC_ADMIN_PASSWORD \
    NUXT_PUBLIC_OIDC_ISSUER=$NUXT_PUBLIC_OIDC_ISSUER \
    NUXT_PUBLIC_OIDC_CLIENT_ID=$NUXT_PUBLIC_OIDC_CLIENT_ID \
    NUXT_PUBLIC_OIDC_REDIRECT_URI=$NUXT_PUBLIC_OIDC_REDIRECT_URI \
    NUXT_PUBLIC_OIDC_SCOPES=$NUXT_PUBLIC_OIDC_SCOPES

RUN pnpm generate

FROM nginx:1.27-alpine AS runtime
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/.output/public /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1/healthz || exit 1
CMD ["nginx", "-g", "daemon off;"]
