FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC

# set dependencies
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

RUN wget -O litecoin.tar.gz https://download.litecoin.org/litecoin-0.21.2.2/linux/litecoin-0.21.2.2-x86_64-linux-gnu.tar.gz \
    && tar -xzf litecoin.tar.gz \
    && cp litecoin-0.21.2.2/bin/* /usr/local/bin/ \
    && rm -rf litecoin-0.21.2.2 litecoin.tar.gz

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .


