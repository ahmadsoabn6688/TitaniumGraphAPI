# Builds the gqlgate gateway WITH whatever .go files are in hooks/ compiled in.
# `go mod tidy` runs during the build, so hooks may import any third-party
# library and it resolves automatically — no manual dependency management.
FROM golang:1.26 AS build
WORKDIR /src

# Warm the module cache first for faster rebuilds.
COPY go.mod go.sum ./
RUN go mod download

# Bring in the full source (including hooks/) and resolve any new imports the
# hook files added, then build static binaries.
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o /out/gqlgate ./cmd/gqlgate \
 && CGO_ENABLED=0 go build -o /out/gqlgate-seed ./example/seed

FROM alpine:3
RUN apk add --no-cache ca-certificates
COPY --from=build /out/gqlgate /out/gqlgate-seed /usr/local/bin/
EXPOSE 8080
ENTRYPOINT ["gqlgate"]
CMD ["-config", "/etc/gqlgate/gqlgate.yaml"]
