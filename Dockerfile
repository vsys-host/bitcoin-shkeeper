FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC

# Установим зависимости
RUN apt-get update && apt-get install -y \
    wget build-essential libffi-dev libssl-dev libgmp-dev \
    libpq-dev default-libmysqlclient-dev pkg-config git \
    && rm -rf /var/lib/apt/lists/*

# server
RUN wget https://bitcoincore.org/bin/bitcoin-core-27.0/bitcoin-27.0-x86_64-linux-gnu.tar.gz \
    && tar -xzf bitcoin-27.0-x86_64-linux-gnu.tar.gz \
    && cp bitcoin-27.0/bin/* /usr/local/bin/ \
    && rm -rf bitcoin-27.0*

# local
# RUN wget https://bitcoincore.org/bin/bitcoin-core-27.0/bitcoin-27.0-aarch64-linux-gnu.tar.gz \
#     && tar -xzf bitcoin-27.0-aarch64-linux-gnu.tar.gz \
#     && cp bitcoin-27.0/bin/* /usr/local/bin/ \
#     && rm -rf bitcoin-27.0 bitcoin-27.0-aarch64-linux-gnu.tar.gz

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .


