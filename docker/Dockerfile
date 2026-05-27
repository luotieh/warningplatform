FROM docker.1ms.run/alpine:3.21

WORKDIR /app

# 换源 + 时区 + Chromium（截图功能依赖浏览器）+ 中文字体
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apk/repositories && \
    apk update && \
    apk add --no-cache \
        tzdata \
        chromium \
        nss \
        freetype \
        harfbuzz \
        font-noto-cjk && \
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
