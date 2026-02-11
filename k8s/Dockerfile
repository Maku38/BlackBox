# Use latest Ubuntu to match your host system's libraries
FROM ubuntu:latest

# Install eBPF runtime dependencies AND libbpf
RUN apt-get update && apt-get install -y \
    libelf1 \
    zlib1g \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY blackbox /app/blackbox

EXPOSE 8080
CMD ["/app/blackbox"]