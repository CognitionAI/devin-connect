# Devin Gateway — the customer-deployed gateway ships as a fully static musl
# binary so the runtime stage can be FROM scratch (no OS, no libc, no shell).
# The gateway's TLS stack is rustls + webpki-roots (CA roots compiled in), so
# nothing outside the binary is needed at runtime.
#
# Builds natively for linux/amd64 and linux/arm64 (TARGETARCH selects the
# musl target).
ARG TINI_VERSION=v0.19.0
ARG TINI_SHA256=0fd35a7030052acd9f58948d1d900fe1e432ee37103c5561554408bdac6bbf0d
ARG CARGO_AUDITABLE_VERSION=0.7.5
ARG CARGO_AUDITABLE_SHA256_AMD64=3374daaf153e6f82028add5e4bf7cc2deab46537dee24f20be80df831193aeb4
ARG CARGO_AUDITABLE_SHA256_ARM64=35d90cee9648037eaa4c1a2649fdca9d1b9a9997b972d37be7f8629139ba1294
ARG CARGO_ABOUT_VERSION=0.9.2
ARG CARGO_ABOUT_SHA256_AMD64=9099a59e820c38a68b9d65f300662a567d56562f9a10f6aa4c7e86c17c2566af
ARG CARGO_ABOUT_SHA256_ARM64=af5169282fb6f84e13471493f405437e43ac517744c9ae12fbe2cdf0a6f0e5a8
ARG RUST_LLVM_REV=c1118fdbb3024157df7f4cfe765f2b0b4339e8a2
ARG LIBUNWIND_LICENSE_SHA256=b5efebcaca80879234098e52d1725e6d9eb8fb96a19fce625d39184b705f7b6d

FROM rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS builder

ARG TARGETARCH
ARG TINI_VERSION
ARG TINI_SHA256
ARG CARGO_AUDITABLE_VERSION
ARG CARGO_AUDITABLE_SHA256_AMD64
ARG CARGO_AUDITABLE_SHA256_ARM64
ARG CARGO_ABOUT_VERSION
ARG CARGO_ABOUT_SHA256_AMD64
ARG CARGO_ABOUT_SHA256_ARM64
ARG RUST_LLVM_REV
ARG LIBUNWIND_LICENSE_SHA256

RUN apt-get update -yqq && \
    apt-get install -y --no-install-recommends ca-certificates cmake curl make musl-tools python3 xz-utils && \
    rm -rf /var/lib/apt/lists/*

RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH '$TARGETARCH'" >&2; exit 1 ;; \
    esac > /rust-target && \
    rustup target add "$(cat /rust-target)"

# cargo-auditable embeds the resolved dependency list (Cargo.lock subset that
# actually went into the binary) in a .dep-v0 ELF section, so SBOM scanners
# (syft, trivy, cargo audit bin) can inventory the crates from the binary alone
# — the FROM scratch image has no package manager to inventory otherwise.
RUN case "$TARGETARCH" in \
      amd64) _triple=x86_64-unknown-linux-musl;  _sha="$CARGO_AUDITABLE_SHA256_AMD64" ;; \
      arm64) _triple=aarch64-unknown-linux-musl; _sha="$CARGO_AUDITABLE_SHA256_ARM64" ;; \
    esac && \
    curl -fsSL --retry 5 --retry-delay 10 --retry-all-errors \
      "https://github.com/rust-secure-code/cargo-auditable/releases/download/v${CARGO_AUDITABLE_VERSION}/cargo-auditable-${_triple}.tar.xz" \
      -o /tmp/cargo-auditable.tar.xz && \
    echo "${_sha}  /tmp/cargo-auditable.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/cargo-auditable.tar.xz -C /usr/local/cargo/bin --strip-components=1 "cargo-auditable-${_triple}/cargo-auditable" && \
    rm /tmp/cargo-auditable.tar.xz

RUN case "$TARGETARCH" in \
      amd64) _sha="$CARGO_ABOUT_SHA256_AMD64" ;; \
      arm64) _sha="$CARGO_ABOUT_SHA256_ARM64" ;; \
    esac && \
    _archive="cargo-about-${CARGO_ABOUT_VERSION}-$(cat /rust-target)" && \
    curl -fsSL --retry 5 --retry-delay 10 --retry-all-errors \
      "https://github.com/EmbarkStudios/cargo-about/releases/download/${CARGO_ABOUT_VERSION}/${_archive}.tar.gz" \
      -o /tmp/cargo-about.tar.gz && \
    echo "${_sha}  /tmp/cargo-about.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/cargo-about.tar.gz -C /usr/local/cargo/bin --strip-components=1 "${_archive}/cargo-about" && \
    rm /tmp/cargo-about.tar.gz

# tini (static, PID 1 for signal handling in the scratch image).
RUN mkdir -p /output/licenses/tini /tmp/tini && \
    curl -fsSL --retry 5 --retry-delay 10 --retry-all-errors \
      "https://github.com/krallin/tini/archive/refs/tags/${TINI_VERSION}.tar.gz" -o /tmp/tini.tar.gz && \
    echo "${TINI_SHA256}  /tmp/tini.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/tini.tar.gz -C /tmp/tini --strip-components=1 && \
    cmake -S /tmp/tini -B /tmp/tini-build -DCMAKE_C_COMPILER=musl-gcc && \
    cmake --build /tmp/tini-build --target tini-static && \
    cp /tmp/tini-build/tini-static /output/tini && \
    cp /tmp/tini/LICENSE /output/licenses/tini/LICENSE

WORKDIR /build
COPY . /build

FROM builder AS gateway-builder

RUN mkdir -p /output/licenses/rust && \
    cargo about generate --locked --fail --manifest-path gateway/Cargo.toml \
      --target "$(cat /rust-target)" --config about.toml \
      --output-file /output/licenses/THIRD-PARTY-LICENSES.txt about.hbs && \
    cargo metadata --locked --format-version 1 --filter-platform "$(cat /rust-target)" > /tmp/license-metadata.json && \
    python3 scripts/collect-notices.py /tmp/license-metadata.json /output/licenses/notices && \
    cp "$(rustc --print sysroot)/share/doc/rust/COPYRIGHT-library.html" /output/licenses/rust/ && \
    cp -r "$(rustc --print sysroot)/share/doc/rust/licenses" /output/licenses/rust/ && \
    cp /usr/share/doc/musl/copyright /output/licenses/musl-copyright && \
    curl -fsSL --retry 5 --retry-delay 10 --retry-all-errors \
      "https://raw.githubusercontent.com/rust-lang/llvm-project/${RUST_LLVM_REV}/libunwind/LICENSE.TXT" \
      -o /output/licenses/rust/libunwind-LICENSE.TXT && \
    echo "${LIBUNWIND_LICENSE_SHA256}  /output/licenses/rust/libunwind-LICENSE.TXT" | sha256sum -c -

RUN --mount=type=cache,target=/build/target/ \
  cargo auditable build --locked --release -p gateway --target "$(cat /rust-target)" && \
  cp "target/$(cat /rust-target)/release/gateway" /output/

# A dynamically linked binary would only fail at runtime inside FROM scratch;
# fail the build instead. Rust musl targets emit static-pie, so check the ELF
# directly (no PT_INTERP, no DT_NEEDED) rather than parsing ldd's output.
RUN for binary in /output/gateway /output/tini; do \
      readelf -h "$binary" >/dev/null && \
      ! readelf -lW "$binary" | grep -q INTERP && \
      ! readelf -dW "$binary" | grep -q NEEDED || exit 1; \
    done

# Single static binary, no OS. tini (also static) is PID 1 for signal
# handling. The numeric USER is required because scratch has no /etc/passwd.
FROM scratch AS gateway

COPY --from=gateway-builder /output/gateway /gateway
COPY --from=gateway-builder /output/tini /tini
COPY LICENSE /licenses/devin-connect/LICENSE
COPY --from=gateway-builder /output/licenses/ /licenses/third-party/

USER 65532:65532

ENTRYPOINT ["/tini", "--", "/gateway"]
CMD ["serve", "--config", "/etc/devin-gateway/config.yaml"]
