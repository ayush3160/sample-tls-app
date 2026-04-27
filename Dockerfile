# Two-stage build keeps the runtime image small enough that pulling it
# onto a kind/minikube node is essentially free. The runtime stage is
# distroless static — no shell, no libc, just the binary — so the
# attack surface is minimal and we don't need to think about CVE
# scanners flagging Debian/Alpine packages we don't use.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/sample-tls-app .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sample-tls-app /sample-tls-app
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/sample-tls-app"]
