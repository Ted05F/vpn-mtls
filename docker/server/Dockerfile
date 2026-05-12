# docker/server/Dockerfile — VPN Server build
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /bin/vpn-server ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache ca-certificates iproute2 iptables curl
COPY --from=builder /bin/vpn-server /usr/local/bin/vpn-server
ENTRYPOINT ["/usr/local/bin/vpn-server"]
