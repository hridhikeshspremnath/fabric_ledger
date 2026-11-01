# Chaincode-as-a-service image. Requires go.sum (run scripts/chaincode-tidy.sh once).
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/attesta-trust .

FROM alpine:3.20
COPY --from=build /out/attesta-trust /usr/local/bin/attesta-trust
USER 10001
ENTRYPOINT ["/usr/local/bin/attesta-trust"]
