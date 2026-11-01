# Fabric bridge image. Requires go.sum (run scripts/bridge-tidy.sh once).
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/attesta-bridge .

FROM alpine:3.20
COPY --from=build /out/attesta-bridge /usr/local/bin/attesta-bridge
# Runs as the uid registered in SPIRE for this workload (set by compose `user:`).
ENTRYPOINT ["/usr/local/bin/attesta-bridge"]
