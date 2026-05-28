FROM docker.1ms.run/alpine:3.21

WORKDIR /app

# 换源 + 安装核心依赖（已去重并补全关键图形库）
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apk/repositories && \
    apk update && \
    apk add --no-cache \
        tzdata \
        chromium \
        nss \
        freetype \
        harfbuzz \
        font-noto-cjk \
        dbus-libs \
        mesa-vulkan-swrast \
        libx11 \
        libxcb \
        libxcomposite \
        libxdamage \
        libxext \
        libxfixes \
        libxrandr \
        libxrender \
        libxshmfence \
        libxxf86vm \
        atk \
        at-spi2-atk \
        cups-libs \
        pango \
        cairo \
        libepoxy \
        glib && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    apk del tzdata && \
    rm -rf /var/cache/apk/*

# Chromium 路径供 go-rod 自动发现
ENV CHROME_BIN=/usr/bin/chromium-browser

EXPOSE 8080

ARG TARGETPLATFORM
COPY server-${TARGETPLATFORM#linux/} ./server

ARG MODE=dev
COPY *.config.toml ./configs/
RUN if [ -f "./configs/${MODE}.config.toml" ]; then \
        cp "./configs/${MODE}.config.toml" "./config.toml" && \
        echo "Config loaded: ${MODE}.config.toml"; \
    else \
        echo "Warning: Config file for mode '${MODE}' not found."; \
    fi

RUN chmod +x ./server

CMD ["/app/server"]
