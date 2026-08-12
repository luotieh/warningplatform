#!/usr/bin/env bash
# 本地构建 warning-platform ARM64 部署镜像（复刻 .gitea/workflows/dev.yaml 的构建配方）。
#
# 用法：
#   scripts/build-arm-image.sh                 # 全流程：前端 → wire → arm64 编译 → 镜像 → tar
#   scripts/build-arm-image.sh --skip-frontend # 跳过前端构建（vulnscan-backend/frontend/dist 已是最新时）
#
# 前置条件：
#   1. 办公网隧道可用（go mod download 需要 code.yt-security.com 的私有模块）；
#   2. Docker Desktop 运行中（WSL 里没有 docker CLI 时自动改用 Windows 侧 docker.exe）。
#
# 产物：dist-image/warning-platform-<TAG>-arm64.tar.gz（docker load 即可部署）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${MODE:-dev}"
ARCH="${ARCH:-arm64}"
SKIP_FRONTEND=false
[ "${1:-}" = "--skip-frontend" ] && SKIP_FRONTEND=true

# ── docker CLI 选择：WSL 原生 docker 优先，缺失则用 Windows 侧 docker.exe ──
DOCKER_BIN="docker"
CONTEXT_ON_WINDOWS=false
if ! command -v docker >/dev/null 2>&1; then
  DOCKER_BIN="/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe"
  CONTEXT_ON_WINDOWS=true
  [ -x "$DOCKER_BIN" ] || { echo "❌ 找不到 docker，也找不到 Windows 侧 docker.exe"; exit 1; }
fi
"$DOCKER_BIN" version --format '{{.Server.Version}}' >/dev/null 2>&1 || {
  echo "❌ Docker 引擎未运行，请先启动 Docker Desktop"; exit 1; }

COMMIT_SHORT=$(git -C "$ROOT" rev-parse --short=6 HEAD)
TAG="${MODE}.$(date +%Y%m%d).$(date +%H%M%S)"
IMAGE="warning-platform:${TAG}-${ARCH}"

# ── (1) 前端构建（产物直接输出到 vulnscan-backend/frontend/dist）──
if [ "$SKIP_FRONTEND" = false ]; then
  echo "━━ (1/4) 构建前端 ━━"
  (cd "$ROOT/vulnscan-frontend" \
    && NODE_OPTIONS="--max-old-space-size=6144" GENERATE_SOURCEMAP=false pnpm run build:prod)
else
  echo "━━ (1/4) 跳过前端构建（--skip-frontend）━━"
fi
[ -f "$ROOT/vulnscan-backend/frontend/dist/index.html" ] || {
  echo "❌ vulnscan-backend/frontend/dist 缺少产物"; exit 1; }

# ── (2) 后端 arm64 交叉编译（wire_gen.go 被 gitignore，必须现场生成）──
echo "━━ (2/4) 编译后端 (linux/${ARCH}) ━━"
cd "$ROOT/vulnscan-backend"
go mod download
(cd di && go run github.com/google/wire/cmd/wire)

BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GO_VERSION=$(go version | awk '{print $3}')
LDFLAGS="-s -w -extldflags '-static'"
LDFLAGS+=" -X 'vulnscan-backend/boot.BuildTime=${BUILD_TIME}'"
LDFLAGS+=" -X 'vulnscan-backend/boot.BuildHash=${COMMIT_SHORT}'"
LDFLAGS+=" -X 'vulnscan-backend/boot.GoVersion=${GO_VERSION}'"
LDFLAGS+=" -X 'vulnscan-backend/boot.ProductVersion=${TAG}'"
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -ldflags "$LDFLAGS" -trimpath \
  -o "$ROOT/server-${ARCH}" ./cmd/server
echo "✅ server-${ARCH}: $(ls -lh "$ROOT/server-${ARCH}" | awk '{print $5}')"

# ── (3) 准备构建上下文并打镜像 ──
# docker.exe（Windows 守护进程）读不了 WSL 路径，上下文放到 Windows 临时目录。
echo "━━ (3/4) 构建镜像 ${IMAGE} ━━"
if [ "$CONTEXT_ON_WINDOWS" = true ]; then
  CTX="/mnt/c/Users/10130/AppData/Local/Temp/warning-platform-armbuild"
else
  CTX="$(mktemp -d)"
fi
rm -rf "$CTX" && mkdir -p "$CTX"
# docker.1ms.run 镜像源缺 arm64 层，换 docker.io 官方 alpine（同版本内容一致）
sed 's|^FROM docker.1ms.run/alpine:3.21|FROM alpine:3.21|' "$ROOT/docker/Dockerfile" > "$CTX/Dockerfile"
cp "$ROOT/server-${ARCH}" "$CTX/server-${ARCH}"
CONFIG_SRC="$ROOT/vulnscan-backend/${MODE}.config.toml"
[ -f "$CONFIG_SRC" ] || CONFIG_SRC="$ROOT/vulnscan-backend/config.toml"
cp "$CONFIG_SRC" "$CTX/${MODE}.config.toml"

(cd "$CTX" && "$DOCKER_BIN" build \
  --platform "linux/${ARCH}" \
  --build-arg MODE="${MODE}" \
  --label "org.opencontainers.image.revision=${COMMIT_SHORT}" \
  --label "org.opencontainers.image.version=${TAG}" \
  -t "$IMAGE" .)

# ── (4) 导出部署 tar ──
echo "━━ (4/4) 导出镜像 tar ━━"
OUT="$ROOT/dist-image"
mkdir -p "$OUT"
if [ "$CONTEXT_ON_WINDOWS" = true ]; then
  # docker.exe -o 写 WSL 路径会失败，先落 Windows 侧再搬运
  "$DOCKER_BIN" save -o "$(wslpath -w "$CTX")\\image.tar" "$IMAGE"
  mv "$CTX/image.tar" "$OUT/warning-platform-${TAG}-${ARCH}.tar"
else
  "$DOCKER_BIN" save -o "$OUT/warning-platform-${TAG}-${ARCH}.tar" "$IMAGE"
fi
gzip -f "$OUT/warning-platform-${TAG}-${ARCH}.tar"
rm -rf "$CTX" "$ROOT/server-${ARCH}"

echo ""
echo "✅ 完成：$OUT/warning-platform-${TAG}-${ARCH}.tar.gz"
ls -lh "$OUT/warning-platform-${TAG}-${ARCH}.tar.gz"
echo ""
echo "部署（ARM 目标机）："
echo "  docker load -i warning-platform-${TAG}-${ARCH}.tar.gz"
echo "  docker run -d --name warning-platform -p 8080:8080 ${IMAGE}"
