FROM python:3.12-slim

LABEL org.opencontainers.image.title="WhoProbe" \
      org.opencontainers.image.description="128-probe L3-L7 browser & network fingerprint / disguise inspector" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY probe.py ./probe.py
COPY static ./static

# Run built-in verification during build
RUN python3 /app/probe.py --self-test

EXPOSE 8899

# Standard HTTP mode by default.
# For passive Linux L3/L4 TCP SYN & TLS JA4 sniffing on host NIC (e.g. eth0):
#   docker run --net=host --cap-add=NET_RAW whoprobe \
#     python3 /app/probe.py --host 127.0.0.1 --port 8899 --sniff-iface eth0 --sniff-port 443
CMD ["python3", "/app/probe.py", "--host", "0.0.0.0", "--port", "8899"]
