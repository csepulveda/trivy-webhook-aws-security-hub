FROM golang:1.26-alpine3.24 AS builder
ARG TARGETOS TARGETARCH TARGETVARIANT
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH  go build -ldflags "-s -w" -o main main.go

FROM alpine:3.24
RUN apk update && apk upgrade --no-cache libcrypto3 libssl3 openssl && apk --no-cache add ca-certificates
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder /app/main .
USER app
ENTRYPOINT ["./main"]