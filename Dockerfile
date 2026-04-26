# Build stage
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /build

COPY go.mod ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG GIT_HASH=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
    -X main.version=${VERSION} \
    -X main.gitHash=${GIT_HASH} \
    -X main.gitBranch=${GIT_BRANCH} \
    -X main.buildTime=${BUILD_TIME}" \
    -o appoller ./cmd/main.go

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /build/appoller /usr/local/bin/appoller

EXPOSE 8089

ENTRYPOINT ["/usr/local/bin/appoller"]
