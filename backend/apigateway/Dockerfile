FROM golang:1.24-alpine AS builder
WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server .

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata wget

WORKDIR /root/

COPY --from=builder /app/server .

COPY --from=builder /app/config.json ./config.json

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:8080/health || exit 1

CMD ["./server"]