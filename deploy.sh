#!/bin/bash
set -euo pipefail

# ═══════════════════════════════════════════
# 一键部署脚本 — 加载镜像 + 重启容器
# 用法: ./deploy.sh <镜像tar文件>
#   例: ./deploy.sh warning-platform-arm64.tar
# ═══════════════════════════════════════════

APP_DIR="/data/app"
COMPOSE_FILE="${APP_DIR}/docker-compose.yaml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $*"; }
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

if [ $# -lt 1 ]; then
  echo "用法: $0 <镜像tar文件>"
  echo "  例: $0 warning-platform-arm64.tar"
  exit 1
fi

TAR_FILE="$1"

if [ ! -f "$TAR_FILE" ]; then
  err "镜像文件不存在: $TAR_FILE"
fi

# Step 1: 加载镜像
log "正在加载 Docker 镜像: ${TAR_FILE}"
LOAD_OUTPUT=$(docker load -i "$TAR_FILE" 2>&1)
echo "$LOAD_OUTPUT"

IMAGE_NAME=$(echo "$LOAD_OUTPUT" | grep -oP 'Loaded image: \K.*' | tail -1)
if [ -z "$IMAGE_NAME" ]; then
  IMAGE_NAME=$(echo "$LOAD_OUTPUT" | grep -oP 'Loaded image ID: \K.*' | tail -1)
fi
ok "镜像加载完成: ${IMAGE_NAME:-未知}"

# Step 2: 更新 docker-compose.yaml 中的镜像 tag（如果检测到新 tag）
if [ -n "$IMAGE_NAME" ] && [ -f "$COMPOSE_FILE" ]; then
  REPO=$(echo "$IMAGE_NAME" | cut -d: -f1)
  TAG=$(echo "$IMAGE_NAME" | cut -d: -f2-)
  if [ -n "$REPO" ] && [ -n "$TAG" ] && [ "$REPO" != "$TAG" ]; then
    log "检测到镜像: ${REPO}:${TAG}"
    # 备份
    cp "$COMPOSE_FILE" "${COMPOSE_FILE}.bak.$(date '+%Y%m%d%H%M%S')"
    # 替换同仓库名的镜像 tag
    ESCAPED_REPO=$(echo "$REPO" | sed 's/[\/&]/\\&/g')
    if grep -q "${ESCAPED_REPO}" "$COMPOSE_FILE"; then
      sed -i "s|${ESCAPED_REPO}:[^ ]*|${REPO}:${TAG}|g" "$COMPOSE_FILE"
      ok "已更新 docker-compose.yaml 中的镜像 tag"
    else
      warn "docker-compose.yaml 中未找到 ${REPO}，请手动确认"
    fi
  fi
fi

# Step 3: 停止旧容器
log "正在停止现有容器..."
cd "$APP_DIR"
docker compose down
ok "容器已停止"

# Step 4: 启动新容器
log "正在启动新容器..."
docker compose up -d
ok "容器已启动"

# Step 5: 显示运行状态
echo ""
log "当前容器状态:"
docker compose ps
echo ""
ok "部署完成！"
