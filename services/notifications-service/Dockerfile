FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

# Resolve new dependencies added to go.mod
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -o notifications-service .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/notifications-service .

EXPOSE 8082

CMD ["./notifications-service"]
