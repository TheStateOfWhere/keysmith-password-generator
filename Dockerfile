FROM node:24.21.0-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
COPY public ./public
COPY scripts ./scripts
COPY tests ./tests
COPY data ./data
# Configuration regression tests run inside the build stage as well as locally.
COPY compose.yaml compose.traefik.yaml compose.caddy.yaml .gitignore .dockerignore Dockerfile LICENSE ./
COPY examples ./examples
RUN npm test

FROM nginx:1.30.5-alpine@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94
# Manual security correction on the pinned Alpine 3.24 base. Fail if exact fixes
# are unavailable; do not upgrade Nginx, switch branches or remove dependencies.
RUN apk add --no-cache --upgrade \
      libexpat=2.8.5-r0 pcre2=10.49-r0 tiff=4.7.2-r0 \
      libpng=1.6.59-r0 nghttp2-libs=1.70.0-r0 zlib=1.3.2-r1
LABEL org.opencontainers.image.title="Zevyrn" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.description="Browser-only password generator with local validation and no password storage"
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build --chown=10001:10001 /app/dist /usr/share/nginx/html
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
# Bypass the stock entrypoint scripts so startup never writes to /etc/nginx.
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
