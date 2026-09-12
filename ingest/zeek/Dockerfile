FROM zeek/zeek:latest

# Install tcpreplay, inotify-tools, and runtime utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpreplay \
    inotify-tools \
    bash \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /zeek

COPY local.zeek /zeek/local.zeek
RUN mkdir -p /usr/local/zeek/share/zeek/site && \
    cp /zeek/local.zeek /usr/local/zeek/share/zeek/site/local.zeek

COPY entrypoint.sh /zeek/entrypoint.sh
RUN chmod +x /zeek/entrypoint.sh

VOLUME ["/pcaps", "/logs"]

ENTRYPOINT ["/zeek/entrypoint.sh"]
