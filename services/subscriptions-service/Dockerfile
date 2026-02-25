FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY . .
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -o subscriptions-service .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/subscriptions-service .

EXPOSE 8083

CMD ["./subscriptions-service"]
