#!/bin/sh
# Stand-in remote pi: records what it was started with, then exits 0.
{ echo "ARGS $*"; echo "EXAMPLE_VAR ${EXAMPLE_VAR-unset}"; echo "CWD $(pwd)"; } > "${STUB_PI_OUT:?}"
exit 0
