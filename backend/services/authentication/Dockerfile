FROM golang:1.24.4-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod tidy

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server ./cmd

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

COPY --from=builder /app/server .

COPY .env .

EXPOSE 8080

CMD ["./server"]
