FROM ubuntu:plucky

# ── Base toolchain: clang + meson + ninja ────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential python3 python3-pip ninja-build pkg-config \
        git wget ca-certificates gnupg lsb-release \
    && rm -rf /var/lib/apt/lists/*

# ncc currently requires Clang 22.1.0+ for C23 #embed / --embed-dir.
RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/llvm.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/llvm.gpg] \
        http://apt.llvm.org/plucky/ llvm-toolchain-plucky-22 main" \
        > /etc/apt/sources.list.d/llvm.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends clang-22 lld-22 \
    && ln -sf /usr/bin/clang-22   /usr/bin/clang \
    && ln -sf /usr/bin/clang++-22 /usr/bin/clang++ \
    && rm -rf /var/lib/apt/lists/*

# meson >= 1.6.0 (repo version may be too old).
RUN pip3 install --break-system-packages 'meson>=1.6.0'

RUN clang --version && meson --version

# ── Windows cross-compiler (always available) ────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc-mingw-w64-x86-64 \
    && rm -rf /var/lib/apt/lists/*

# ── libsecret-1 (Linux secret-handle bridge) + headless test deps ───────────
# libsecret-1-dev gives us the headers + lib; gnome-keyring + dbus + at-spi
# are needed to spin up a Secret Service daemon at test time so the bridge
# can actually exchange a credential.  test_quic_secret_libsecret SKIPs when
# no daemon is reachable; in CI we wrap test runs with dbus-run-session and
# pre-unlock the keyring so the full happy path is exercised.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libsecret-1-dev libglib2.0-dev \
        gnome-keyring dbus-x11 \
    && rm -rf /var/lib/apt/lists/*

# libgit2 (required dependency since upstream main #99 — meson.build:443).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgit2-dev \
    && rm -rf /var/lib/apt/lists/*

# ── macOS cross-compiler (osxcross, only if SDK tarball provided) ────────────
#
# To enable macOS cross-compilation:
#   1. bash docker/prepare-sdk.sh /path/to/MacOSX15.2.sdk.tar.xz
#   2. docker build -t n00b-linux \
#        --build-arg MACOS_SDK=MacOSX15.2.sdk.tar.xz docker/
#
# When MACOS_SDK is empty (default), this section is a no-op and the image
# still builds with Linux native + Windows cross-compilation support.

ARG MACOS_SDK=""
COPY sdk/ /tmp/sdk/
RUN if [ -n "$MACOS_SDK" ] && [ -f "/tmp/sdk/$MACOS_SDK" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            cmake libssl-dev libxml2-dev zlib1g-dev libbz2-dev patch xz-utils \
        && rm -rf /var/lib/apt/lists/* \
        && git clone --depth=1 https://github.com/tpoechtrager/osxcross /tmp/osxcross \
        && cp "/tmp/sdk/$MACOS_SDK" /tmp/osxcross/tarballs/ \
        && cd /tmp/osxcross \
        && UNATTENDED=1 TARGET_DIR=/usr/local/osxcross ./build.sh \
        && rm -rf /tmp/osxcross; \
    fi \
    && rm -rf /tmp/sdk

ENV CC=clang PATH="/usr/local/osxcross/bin:${PATH}"
WORKDIR /src
