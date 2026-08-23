FROM rust:slim-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    cmake \
    libncursesw5-dev \
    libssl-dev \
    pkg-config \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/grin-wallet
COPY . .
RUN cargo build --release --locked

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/grin-wallet/target/release/grin-wallet /usr/local/bin/grin-wallet

WORKDIR /root/.grin
VOLUME ["/root/.grin"]

ENTRYPOINT ["grin-wallet"]
CMD ["--help"]
