#!/usr/bin/env bash
#
# Builds Unbound with Python module support and runs PFUI_Unbound inside it.
# The build takes a few minutes; nothing here touches the host.
#
#   ./client-unbound/tests/container/run.sh                        # latest release
#   ./client-unbound/tests/container/run.sh release-1.25.2         # a pinned tag
#   ./client-unbound/tests/container/run.sh master                 # upstream head
#
# The build context is the repository root, because the container needs both the
# client and the shared protocol module.

set -eu

UNBOUND_VERSION=${1:-latest}
HERE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT="$( cd "${HERE}/../../.." >/dev/null 2>&1 && pwd )"
IMAGE="pfui-unbound-test:${UNBOUND_VERSION}"

echo "Building ${IMAGE} from ${ROOT} (Unbound ${UNBOUND_VERSION})"
docker build \
  --build-arg "UNBOUND_VERSION=${UNBOUND_VERSION}" \
  -f "${HERE}/Dockerfile" \
  -t "${IMAGE}" \
  "${ROOT}"

echo
echo "Running PFUI_Unbound inside it"
# Loopback only: nsd, the resolver and the stub firewall all talk to each other
# inside the container, so nothing is published to the host
docker run --rm "${IMAGE}"
