#!/bin/bash
set -e

GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DEFAULT_VERSION="1.0.0"
OUTPUT_DIR="bin"

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -v, --version       Set version (default: $DEFAULT_VERSION)"
    echo "  -s, --server        Build MCP server binary"
    echo "  -d, --docker        Build Docker image"
    echo "  -p, --platform      Docker target platform (default: current Docker daemon platform)"
    echo "      --with-pcap-tools"
    echo "                      Include tshark/capinfos for richer pcap inspection"
    echo "      --legacy-builder"
    echo "                      Disable BuildKit and use the local Docker builder"
    echo "  -c, --clean         Clean build artifacts"
    echo ""
    echo "Examples:"
    echo "  $0 -s               Build MCP server only"
    echo "  $0 -v 1.1.0 -s -d   Build with version 1.1.0 and Docker image"
    echo "  $0 -d -p linux/amd64 Build Docker image for linux/amd64"
    echo "  $0 -d --with-pcap-tools"
    echo "                       Build Docker image with tshark/capinfos"
    echo "  $0 -d --legacy-builder"
    echo "                       Build from locally cached base images when BuildKit registry metadata lookup fails"
}

BUILD_SERVER=false
BUILD_DOCKER=false
CLEAN=false
VERSION=$DEFAULT_VERSION
PLATFORM=""
WITH_PCAP_TOOLS=false
LEGACY_BUILDER=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) print_usage; exit 0 ;;
        -v|--version) VERSION="$2"; shift 2 ;;
        -s|--server) BUILD_SERVER=true; shift ;;
        -d|--docker) BUILD_DOCKER=true; shift ;;
        -p|--platform) PLATFORM="$2"; shift 2 ;;
        --with-pcap-tools) WITH_PCAP_TOOLS=true; shift ;;
        --legacy-builder) LEGACY_BUILDER=true; shift ;;
        -c|--clean) CLEAN=true; shift ;;
        *) echo "Unknown option: $1"; print_usage; exit 1 ;;
    esac
done

if [[ $BUILD_SERVER == false && $BUILD_DOCKER == false && $CLEAN == false ]]; then
    print_usage
    exit 0
fi

if [[ $CLEAN == true ]]; then
    echo "Cleaning build artifacts..."
    rm -rf "$OUTPUT_DIR"
    rm -f zeek_mcp.tar.gz
    echo "Clean complete!"
    exit 0
fi

mkdir -p "$OUTPUT_DIR"

echo "========================================"
echo "  Zeek MCP Build"
echo "========================================"
echo "Version: $VERSION"
echo "Git Commit: $GIT_COMMIT"
echo "Build Time: $BUILD_TIME"
if [[ -n $PLATFORM ]]; then
    echo "Docker Platform: $PLATFORM"
else
    echo "Docker Platform: current daemon default"
fi
echo "Docker Pcap Tools: $WITH_PCAP_TOOLS"
echo "Docker Legacy Builder: $LEGACY_BUILDER"
echo "========================================"

LDFLAGS="-X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT"

if [[ $BUILD_SERVER == true ]]; then
    echo ""
    echo "Building MCP Server..."
    CGO_ENABLED=0 go build -v -o "$OUTPUT_DIR/zeek_mcp" \
        -ldflags "$LDFLAGS" \
        .
    echo "MCP Server: $OUTPUT_DIR/zeek_mcp"
fi

if [[ $BUILD_DOCKER == true ]]; then
    echo ""
    echo "Building Docker image..."
    DOCKER_BUILD_ARGS=(
        --build-arg "VERSION=$VERSION"
        --build-arg "BUILD_TIME=$BUILD_TIME"
        --build-arg "GIT_COMMIT=$GIT_COMMIT"
        --build-arg "WITH_PCAP_TOOLS=$WITH_PCAP_TOOLS"
        -t "zeek_mcp:$VERSION"
        -t "zeek_mcp:latest"
    )
    if [[ -n $PLATFORM ]]; then
        DOCKER_BUILD_ARGS+=(--platform "$PLATFORM")
    fi
    DOCKER_BUILD_ARGS+=(.)

    if [[ $LEGACY_BUILDER == true ]]; then
        DOCKER_BUILDKIT=0 docker build "${DOCKER_BUILD_ARGS[@]}"
    else
        docker build "${DOCKER_BUILD_ARGS[@]}"
    fi

    echo "Saving image to tarball..."
    docker save zeek_mcp:latest | gzip > zeek_mcp.tar.gz
    echo "Docker Image: zeek_mcp.tar.gz"
fi

echo ""
echo "========================================"
echo "Build complete!"
echo "========================================"
