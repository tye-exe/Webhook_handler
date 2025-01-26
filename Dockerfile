FROM docker.io/rust:1-slim-bookworm AS build

ARG pkg=webhook_handler

WORKDIR /build

COPY . .

RUN --mount=type=cache,target=/build/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    set -eux; \
    cargo build --release; \
    objcopy --compress-debug-sections target/release/$pkg ./main

################################################################################

FROM docker.io/debian:bookworm-slim

# Prep for nix install
RUN apt update \
    && apt-get install -y curl xz-utils \
    && /sbin/useradd -m nixuser \
    && mkdir /nix \
    && chown nixuser /nix \
    && apt-get clean

# Nix install
USER nixuser
ENV USER=nixuser
ENV PATH="/home/nixuser/.nix-profile/bin:${PATH}"
RUN curl -sL https://nixos.org/nix/install | sh -s -- --no-daemon

# Install build tools
RUN nix-env -iA nixpkgs.rustup
RUN nix-env -iA nixpkgs.gccgo # Linker
RUN nix-env -iA nixpkgs.trunk

RUN nix-env -iA nixpkgs.git

USER root

# Install toolchain for wasm
RUN rustup default stable
RUN rustup target add wasm32-unknown-unknown
# RUN groupadd nixbld && usermod -aG nixbld nixuser

WORKDIR /app

## copy the main binary
COPY --from=build /build/main ./

## copy runtime assets which may or may not exist
COPY --from=build /build/Rocket.tom[l] ./static
COPY --from=build /build/stati[c] ./static
COPY --from=build /build/template[s] ./templates

## ensure the container listens globally on port 8080
ENV ROCKET_ADDRESS=0.0.0.0
ENV ROCKET_PORT=8080

CMD ./main
