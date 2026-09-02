#!/usr/bin/env bash
#
# End-to-end: the real PFUI_Unbound against the real Rust PFUI_Firewall.
# Builds the client container (Unbound from source with the Python module —
# a few minutes), the daemon binary (in the MSRV container), and a small
# image layering Redis and a pfctl stub on top; nothing runs on the host.
#
#   ./server-rust/tests/e2e/run.sh                # latest Unbound release
#   ./server-rust/tests/e2e/run.sh release-1.25.2 # a pinned tag

set -eu

UNBOUND_VERSION=${1:-latest}
HERE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT="$( cd "${HERE}/../../.." >/dev/null 2>&1 && pwd )"
CLIENT_IMAGE="pfui-unbound-test:${UNBOUND_VERSION}"
E2E_IMAGE="pfui-rust-e2e:${UNBOUND_VERSION}"
# The bookworm variant matters: the client image is debian:bookworm-slim, and
# a binary built against a newer default base wants a newer glibc than it has
RUST_IMAGE="rust:1.94-bookworm"

# Reuse the client image when it exists: the Unbound build is the slow part,
# and the CI job / client run.sh build the identical image
if ! docker image inspect "${CLIENT_IMAGE}" >/dev/null 2>&1; then
  echo "Building ${CLIENT_IMAGE} (Unbound ${UNBOUND_VERSION}; takes a few minutes)"
  docker build \
    --build-arg "UNBOUND_VERSION=${UNBOUND_VERSION}" \
    -f "${ROOT}/client-unbound/tests/container/Dockerfile" \
    -t "${CLIENT_IMAGE}" \
    "${ROOT}"
fi

echo "Building the daemon (release, locked) in ${RUST_IMAGE}"
# A dedicated target dir: the dev loop builds against a different base image,
# and cargo's freshness check cannot tell the two glibc links apart
docker run --rm \
  -v "${ROOT}":/work \
  -v pfui-cargo-registry:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/work/server-rust/target/e2e \
  -w /work/server-rust \
  "${RUST_IMAGE}" cargo build --release --locked

echo "Building ${E2E_IMAGE}"
docker build \
  --build-arg "BASE=${CLIENT_IMAGE}" \
  -t "${E2E_IMAGE}" \
  "${HERE}"

echo
echo "Running PFUI_Unbound against the Rust daemon (loopback only)"
docker run --rm \
  -v "${ROOT}/server-rust/target/e2e/release/pfui_firewall:/usr/local/sbin/pfui_firewall:ro" \
  "${E2E_IMAGE}"
