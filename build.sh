#!/bin/bash
# ─── Multi-arch build & push for AWG 3.1 Web UI ─────────────────────────────
# Usage:
#   ./build.sh                        # build + push latest
#   ./build.sh --tag v1.2.3           # build + push with version tag
#   ./build.sh --no-push              # build only, no push
#   ./build.sh --local                # build amd64 locally (no push)
#
# Prerequisites:
#   docker buildx create --use --name multiarch --driver docker-container
#   docker login
# ─────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${DOCKER_IMAGE:-sysmslog/awg2-webui}"
PLATFORMS="linux/amd64,linux/arm64"
TAG="latest"
PUSH=true
LOCAL=false

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag|-t)   TAG="$2"; shift 2 ;;
        --no-push)  PUSH=false; shift ;;
        --local)    LOCAL=true; PUSH=false; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AWG 3.1 Web UI — Multi-arch Build"
echo "  Image    : ${IMAGE}:${TAG}"
echo "  Platforms: $PLATFORMS"
echo "  Push     : $PUSH"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if $LOCAL; then
    # Fast local single-arch build (Mac: arm64 native or amd64 emulated)
    HOST_ARCH="$(uname -m)"
    if [ "$HOST_ARCH" = "arm64" ] || [ "$HOST_ARCH" = "aarch64" ]; then
        PLATFORM="linux/arm64"
    else
        PLATFORM="linux/amd64"
    fi
    echo "▶ Local build for $PLATFORM..."
    docker build \
        --platform "$PLATFORM" \
        -t "${IMAGE}:${TAG}" \
        "$SCRIPT_DIR"
    echo ""
    echo "✅ Local image built: ${IMAGE}:${TAG}"
    echo "   Run: docker run -d --name awg2-test -p 80:80 -p 51820:51820/udp ${IMAGE}:${TAG}"
    exit 0
fi

# Ensure buildx builder exists
if ! docker buildx inspect multiarch &>/dev/null; then
    echo "▶ Creating buildx builder 'multiarch'..."
    docker buildx create --name multiarch --driver docker-container --use
else
    docker buildx use multiarch
fi
docker buildx inspect --bootstrap multiarch

echo ""
echo "▶ Building & pushing multi-arch image..."

TAGS="-t ${IMAGE}:${TAG}"
if [ "$TAG" != "latest" ]; then
    TAGS="$TAGS -t ${IMAGE}:latest"
fi

if $PUSH; then
    docker buildx build \
        --platform "$PLATFORMS" \
        $TAGS \
        --push \
        "$SCRIPT_DIR"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  ✅ Pushed: ${IMAGE}:${TAG}"
    [ "$TAG" != "latest" ] && echo "  ✅ Pushed: ${IMAGE}:latest"
    echo ""
    echo "  Pull: docker pull ${IMAGE}:${TAG}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    docker buildx build \
        --platform "$PLATFORMS" \
        $TAGS \
        "$SCRIPT_DIR"
    echo ""
    echo "✅ Build complete (not pushed)"
fi
