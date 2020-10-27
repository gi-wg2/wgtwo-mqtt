FROM golang:alpine as builder

RUN apk update && apk add --no-cache git ca-certificates tzdata upx && update-ca-certificates

ENV USER=appuser
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

WORKDIR /app
COPY go.mod /app/go.mod

ENV GO111MODULE=on
RUN go mod download
RUN go mod verify

WORKDIR /app/cmd/
COPY . /app

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' -a \
    -o /go/bin/app

RUN upx /go/bin/app --best --ultra-brute

FROM scratch
# Use an unprivileged user.
USER appuser:appuser
WORKDIR /wgtwo-mqtt
ENTRYPOINT ["/wgtwo-mqtt/bin"]

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /go/bin/app /wgtwo-mqtt/bin
COPY --from=builder /app/templates/*.html /wgtwo-mqtt/templates/
