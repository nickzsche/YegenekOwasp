FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /temren ./cmd/temren

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /temren /usr/local/bin/temren
COPY action/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
