FROM golang:1.24-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/cordclaw-daemon ./cmd/cordclaw-daemon

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=builder /out/cordclaw-daemon /usr/local/bin/cordclaw-daemon

EXPOSE 19090
ENTRYPOINT ["/usr/local/bin/cordclaw-daemon"]
