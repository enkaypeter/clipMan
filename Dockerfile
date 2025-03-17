FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o clipman ./main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/clipman ./clipman

EXPOSE 8080

ENV MONGO_URI=""
ENV MONGO_DB=""
ENV JWT_SECRET=""
ENV GIN_MODE="release"
ENV PORT=""


ENTRYPOINT ["./clipman"]
