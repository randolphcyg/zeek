ARG ZEEK_VER=8.0.8
ARG GO_VER=1.26.3-alpine
ARG WITH_PCAP_TOOLS=false

ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT

FROM golang:${GO_VER} AS go-builder
ARG VERSION
ARG BUILD_TIME
ARG GIT_COMMIT

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}" -o zeek_mcp .

FROM zeek/zeek:${ZEEK_VER}
ARG WITH_PCAP_TOOLS
ENV TZ=Asia/Shanghai
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH=/usr/local/zeek/bin:${PATH}

RUN apt-get -o Acquire::Retries=3 update && \
    packages="tzdata" && \
    if [ "$WITH_PCAP_TOOLS" = "true" ]; then packages="$packages tshark"; fi && \
    apt-get -o Acquire::Retries=3 install -y --no-install-recommends $packages && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /app/zeek_mcp /app/zeek_mcp
COPY --from=go-builder /app/scripts /app/scripts/

WORKDIR /app
ENTRYPOINT ["/app/zeek_mcp"]
