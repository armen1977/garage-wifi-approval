FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd

ARG TARGETOS
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "arm" ]; then export GOARM=5; fi;     CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/garage-wifi-approval ./cmd/portal

FROM alpine:3.20 AS certificates
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/garage-wifi-approval /garage-wifi-approval
EXPOSE 8080
ENTRYPOINT ["/garage-wifi-approval"]
