# syntax=docker/dockerfile:1

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci || npm install
COPY web/ ./
RUN npm run build

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vpshub ./cmd/vpshub

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/vpshub /app/vpshub
COPY migrations /app/migrations
COPY fingerprints /app/fingerprints
COPY config.yaml /app/config.yaml
ENV VPSHUB_DATA_DIR=/data
ENV VPSHUB_MIGRATIONS=/app/migrations
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/vpshub", "-config", "/app/config.yaml"]
