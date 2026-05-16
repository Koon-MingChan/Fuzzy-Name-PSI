#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTERN_DIR="${SCRIPT_DIR}/extern"
VOLEPSI_DIR="${EXTERN_DIR}/volepsi"
INSTALL_DIR="${SCRIPT_DIR}/install"
MP_SPDZ_DIR="${MP_SPDZ_DIR:-"${SCRIPT_DIR}/../MP-SPDZ"}"
MP_SPDZ_REPO="${MP_SPDZ_REPO:-https://github.com/data61/MP-SPDZ.git}"
MP_SPDZ_JOBS="${MP_SPDZ_JOBS:-2}"
MP_SPDZ_TARGET="${MP_SPDZ_TARGET:-mascot-party.x}"
SETUP_VOLEPSI=1
SETUP_MP_SPDZ=1

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --skip-volepsi       Do not build/install volePSI dependencies.
  --skip-mp-spdz      Do not clone/build MP-SPDZ.
  --mp-spdz-only      Only clone/build MP-SPDZ.
  -h, --help          Show this help text.

Environment:
  MP_SPDZ_DIR         MP-SPDZ checkout path. Default: ${SCRIPT_DIR}/../MP-SPDZ
  MP_SPDZ_JOBS        Parallel make jobs for MP-SPDZ. Default: 2
  MP_SPDZ_TARGET      MP-SPDZ binary target. Default: mascot-party.x
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-volepsi)
            SETUP_VOLEPSI=0
            ;;
        --skip-mp-spdz)
            SETUP_MP_SPDZ=0
            ;;
        --mp-spdz-only)
            SETUP_VOLEPSI=0
            SETUP_MP_SPDZ=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown option '$1'." >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

mkdir -p "${EXTERN_DIR}"

for tool in git python3; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "Error: required tool '${tool}' is not installed or not on PATH." >&2
        exit 1
    fi
done

if [ "${SETUP_VOLEPSI}" -eq 1 ]; then
    for tool in cmake libtoolize autoreconf; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            echo "Error: required tool '${tool}' is not installed or not on PATH." >&2
            exit 1
        fi
    done
fi

if [ "${SETUP_MP_SPDZ}" -eq 1 ]; then
    for tool in make; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            echo "Error: required tool '${tool}' is not installed or not on PATH." >&2
            exit 1
        fi
    done

    if ! command -v clang++ >/dev/null 2>&1 && ! command -v g++ >/dev/null 2>&1; then
        echo "Error: MP-SPDZ needs a C++ compiler. Install clang++ or g++." >&2
        exit 1
    fi
fi

if [ "${SETUP_VOLEPSI}" -eq 1 ]; then
    if [ ! -d "${VOLEPSI_DIR}" ]; then
        git clone --recursive https://github.com/ladnir/volepsi.git "${VOLEPSI_DIR}"
    fi

    cd "${VOLEPSI_DIR}"

    # build.py --setup only configures CMake and does not build/install anything.
    # Run the full build so cryptoTools/libOTe/volePSI are actually installed.
    python3 build.py \
        --install="${INSTALL_DIR}" \
        --par=4 \
        -DVOLE_PSI_ENABLE_BOOST=ON \
        -DVOLE_PSI_ENABLE_SODIUM=ON

    for required_file in \
        "${INSTALL_DIR}/lib/libcryptoTools.a" \
        "${INSTALL_DIR}/lib/liblibOTe.a" \
        "${INSTALL_DIR}/lib/libvolePSI.a" \
        "${INSTALL_DIR}/lib/cmake/cryptoTools/cryptoToolsConfig.cmake"; do
        if [ ! -f "${required_file}" ]; then
            echo "Error: dependency setup did not complete successfully." >&2
            echo "Missing expected file: ${required_file}" >&2
            exit 1
        fi
    done
fi

if [ "${SETUP_MP_SPDZ}" -eq 1 ]; then
    if [ ! -d "${MP_SPDZ_DIR}" ]; then
        git clone --recursive "${MP_SPDZ_REPO}" "${MP_SPDZ_DIR}"
    else
        git -C "${MP_SPDZ_DIR}" submodule update --init --recursive
    fi

    # Build only the binary used by scripts/run_mp_spdz_approx.sh.
    # Keep the default job count modest because MP-SPDZ can exhaust WSL memory.
    make -C "${MP_SPDZ_DIR}" -j"${MP_SPDZ_JOBS}" "${MP_SPDZ_TARGET}"

    for required_file in \
        "${MP_SPDZ_DIR}/compile.py" \
        "${MP_SPDZ_DIR}/Scripts/mascot.sh" \
        "${MP_SPDZ_DIR}/${MP_SPDZ_TARGET}"; do
        if [ ! -e "${required_file}" ]; then
            echo "Error: MP-SPDZ setup did not complete successfully." >&2
            echo "Missing expected file: ${required_file}" >&2
            exit 1
        fi
    done
fi

echo "-------------------------------------------------------"
if [ "${SETUP_VOLEPSI}" -eq 1 ]; then
    echo "volePSI dependencies installed to: ${INSTALL_DIR}"
fi
if [ "${SETUP_MP_SPDZ}" -eq 1 ]; then
    echo "MP-SPDZ installed to: ${MP_SPDZ_DIR}"
    echo "Run scripts use this by default, or set MP_SPDZ_DIR explicitly."
fi
echo "-------------------------------------------------------"
