FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY . .
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -o recommendation-service .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/recommendation-service .

EXPOSE 8086

CMD ["./recommendation-service"]
