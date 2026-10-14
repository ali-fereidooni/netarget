# One image, three static binaries: master (with embedded UI), agent, CLI.
# docker-compose.yml picks the binary per service.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/master ./cmd/master \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agent ./cmd/agent \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/domaindoctor ./cmd/domaindoctor

FROM alpine:3.20
# iputils ping and traceroute are what the agent execs (argument slices, never a shell).
RUN apk add --no-cache ca-certificates iputils traceroute tzdata \
 && adduser -D -H -u 10001 dd \
 && mkdir -p /data/reports && chown dd /data/reports
COPY --from=build /out/ /usr/local/bin/
USER dd
ENV REPORTS_DIR=/data/reports
EXPOSE 8082 9090
# CMD, not ENTRYPOINT: compose's `command:` must replace the binary
# (an ENTRYPOINT would turn `command: [agent]` into an argument to master).
CMD ["/usr/local/bin/master"]
