# syntax=docker/dockerfile:1.7

# === Stage 1: builder ===
FROM kalilinux/kali-rolling@sha256:1fd0364490011f245688c6ed9fee498a11cd779badfbb0b1d3a721d0f49f2d15 AS builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip python3-dev \
        build-essential libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml .
COPY src/ ./src/
COPY README.md .

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip wheel && \
    pip install --no-cache-dir .

# === Stage 2: runtime ===
FROM kalilinux/kali-rolling@sha256:1fd0364490011f245688c6ed9fee498a11cd779badfbb0b1d3a721d0f49f2d15

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        whatweb \
        nikto \
        ca-certificates \
        dnsutils \
        curl && \
    apt-mark hold whatweb nikto && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

RUN useradd -m -u 1000 -s /bin/bash cdt

RUN mkdir -p /app/in /app/out /app/cache && chown -R cdt:cdt /app

USER cdt
WORKDIR /home/cdt

COPY --from=builder --chown=cdt:cdt /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "-m", "cdt"]
CMD ["--help"]
