# docker/client/Dockerfile — VPN Client build
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /bin/vpn-client ./cmd/client

FROM alpine:3.19
RUN apk add --no-cache ca-certificates iproute2 curl
COPY --from=builder /bin/vpn-client /usr/local/bin/vpn-client
ENTRYPOINT ["/usr/local/bin/vpn-client"]
