FROM golang:1.20 as builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY cmd/registry-auth-proxy cmd/registry-auth-proxy
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o registry-auth-proxy cmd/registry-auth-proxy/main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/registry-auth-proxy .
USER 65532:65532

ENTRYPOINT ["/registry-auth-proxy"]
