FROM docker.1ms.run/alpine:3.21

WORKDIR /app

# 换源 + 安装核心依赖
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apk/repositories && \
    apk update && \
    apk add --no-cache \
        tzdata \
        chromium \
        nss \
        freetype \
        harfbuzz \
        font-noto-cjk \
        dbus \
        mesa-dri-gallium \
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
        at-spi2-core \
        cups-libs \
        pango \
        cairo \
        libepoxy \
        glib && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    apk del tzdata && \
    rm -rf /var/cache/apk/*

# Chromium 路径供 go-rod 自动发现；禁用 GPU/Vulkan/D-Bus 避免容器内报错
ENV CHROME_BIN=/usr/bin/chromium-browser
ENV DBUS_SESSION_BUS_ADDRESS=/dev/null

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
