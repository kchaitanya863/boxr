#!/bin/sh
set -e

# boxr Universal POSIX Installer
# Fast, rootless, zero-dependency OCI container engine in Rust
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/kchaitanya863/boxr/main/install.sh | sh
#
# Advanced options:
#   curl -fsSL https://raw.githubusercontent.com/kchaitanya863/boxr/main/install.sh | DRY_RUN=1 sh
#   curl -fsSL https://raw.githubusercontent.com/kchaitanya863/boxr/main/install.sh | VERSION=v0.1.68 sh
#   curl -fsSL https://raw.githubusercontent.com/kchaitanya863/boxr/main/install.sh | BOXR_INSTALL_DIR=/usr/local/bin sh

echo "=========================================="
echo "          Installing boxr 📦             "
echo "  Fast OCI Container Engine & Runtime     "
echo "=========================================="

REPO="kchaitanya863/boxr"

# 1. OS Detection
RAW_OS="$(uname -s)"
case "${RAW_OS}" in
    Linux*)
        OS="linux"
        ;;
    Darwin*)
        OS="macos"
        ;;
    FreeBSD*)
        # FreeBSD Linuxulator compatibility
        OS="linux"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        OS="windows"
        ;;
    *)
        echo "Error: Unsupported operating system: ${RAW_OS}" >&2
        exit 1
        ;;
esac

# 2. CPU Architecture Detection
RAW_ARCH="$(uname -m)"
case "${RAW_ARCH}" in
    x86_64|amd64|x64)
        ARCH="x86_64"
        ;;
    aarch64|arm64|armv8*)
        ARCH="arm64"
        ;;
    *)
        echo "Error: Unsupported CPU architecture: ${RAW_ARCH}" >&2
        echo "Supported architectures: x86_64, arm64" >&2
        exit 1
        ;;
esac

# On Windows (MinGW/MSYS), precompiled releases provide x86_64 zip
if [ "${OS}" = "windows" ]; then
    ARCHIVE_NAME="boxr-windows-${ARCH}.zip"
    BINARY_NAME="boxr.exe"
else
    ARCHIVE_NAME="boxr-${OS}-${ARCH}.tar.gz"
    BINARY_NAME="boxr"
fi

echo "Detected Platform: ${OS} (${ARCH})"

# 3. Release Version Resolution
if [ -n "${VERSION}" ]; then
    case "${VERSION}" in
        v*)
            TAG="${VERSION}"
            ;;
        *)
            TAG="v${VERSION}"
            ;;
    esac
else
    TAG=""
    # First attempt: GitHub Releases API
    if command -v curl >/dev/null 2>&1; then
        TAG="$(curl -fsSL -H "Accept: application/vnd.github.v3+json" "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep -m 1 '"tag_name":' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true)"
    elif command -v wget >/dev/null 2>&1; then
        TAG="$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep -m 1 '"tag_name":' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true)"
    fi

    # Fallback attempt: Redirect on /releases/latest
    if [ -z "${TAG}" ]; then
        if command -v curl >/dev/null 2>&1; then
            EFFECTIVE_URL="$(curl -fsSL -o /dev/null -w "%{url_effective}" "https://github.com/${REPO}/releases/latest" 2>/dev/null || true)"
            BASE_TAG="$(basename "${EFFECTIVE_URL}" 2>/dev/null || true)"
            if [ -n "${BASE_TAG}" ] && [ "${BASE_TAG}" != "latest" ]; then
                TAG="${BASE_TAG}"
            fi
        fi
    fi

    # Static fallback if offline or unreachable
    if [ -z "${TAG}" ] || [ "${TAG}" = "latest" ]; then
        TAG="v0.1.68"
    fi
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE_NAME}"

# 4. Target Directory Resolution
BOXR_HOME="${HOME}/.boxr"
COMPLETIONS_DIR="${BOXR_HOME}/completions"

USE_SUDO=0
if [ -n "${BOXR_INSTALL_DIR}" ]; then
    INSTALL_DIR="${BOXR_INSTALL_DIR}"
elif [ "$(id -u 2>/dev/null || echo 1)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
elif [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    INSTALL_DIR="/usr/local/bin"
    USE_SUDO=1
elif [ -t 0 ] && command -v sudo >/dev/null 2>&1 && sudo -v 2>/dev/null; then
    INSTALL_DIR="/usr/local/bin"
    USE_SUDO=1
else
    INSTALL_DIR="${BOXR_HOME}/bin"
fi

# 5. Handle DRY_RUN mode
if [ "${DRY_RUN}" = "1" ] || [ "${DRY_RUN}" = "true" ]; then
    echo ""
    echo "--- DRY RUN MODE (No changes will be applied) ---"
    echo "  Operating System : ${OS} (${RAW_OS})"
    echo "  Architecture     : ${ARCH} (${RAW_ARCH})"
    echo "  Release Tag      : ${TAG}"
    echo "  Archive Name     : ${ARCHIVE_NAME}"
    echo "  Download URL     : ${DOWNLOAD_URL}"
    echo "  Install Location : ${INSTALL_DIR}/${BINARY_NAME}"
    echo "  Completions Dir  : ${COMPLETIONS_DIR}"
    echo "  Elevation (sudo) : $([ "${USE_SUDO}" -eq 1 ] && echo "yes" || echo "no")"
    echo "------------------------------------------------"
    exit 0
fi

# 6. Prepare Destination Directory
if [ "${USE_SUDO}" -eq 1 ]; then
    sudo mkdir -p "${INSTALL_DIR}"
else
    mkdir -p "${INSTALL_DIR}" 2>/dev/null || {
        INSTALL_DIR="${BOXR_HOME}/bin"
        USE_SUDO=0
        mkdir -p "${INSTALL_DIR}"
    }
fi
mkdir -p "${COMPLETIONS_DIR}"

# 7. Download and Extract Release Archive
TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'boxr-install')"
cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

echo "Downloading ${ARCHIVE_NAME} (${TAG})..."
ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"

if command -v curl >/dev/null 2>&1; then
    curl -fL --progress-bar "${DOWNLOAD_URL}" -o "${ARCHIVE_PATH}"
elif command -v wget >/dev/null 2>&1; then
    wget -q --show-progress -O "${ARCHIVE_PATH}" "${DOWNLOAD_URL}"
else
    echo "Error: curl or wget is required to download boxr." >&2
    exit 1
fi

echo "Extracting ${ARCHIVE_NAME}..."
case "${ARCHIVE_NAME}" in
    *.tar.gz|*.tgz)
        tar -xzf "${ARCHIVE_PATH}" -C "${TMP_DIR}"
        ;;
    *.zip)
        if command -v unzip >/dev/null 2>&1; then
            unzip -q "${ARCHIVE_PATH}" -d "${TMP_DIR}"
        elif command -v python3 >/dev/null 2>&1; then
            python3 -m zipfile -e "${ARCHIVE_PATH}" "${TMP_DIR}"
        else
            echo "Error: unzip or python3 is required to extract zip archives." >&2
            exit 1
        fi
        ;;
esac

# 8. Install Binary
SRC_BIN=""
if [ -f "${TMP_DIR}/bin/${BINARY_NAME}" ]; then
    SRC_BIN="${TMP_DIR}/bin/${BINARY_NAME}"
elif [ -f "${TMP_DIR}/${BINARY_NAME}" ]; then
    SRC_BIN="${TMP_DIR}/${BINARY_NAME}"
else
    echo "Error: Could not find ${BINARY_NAME} inside extracted archive." >&2
    exit 1
fi

if [ "${USE_SUDO}" -eq 1 ]; then
    sudo cp "${SRC_BIN}" "${INSTALL_DIR}/${BINARY_NAME}"
    sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
else
    cp "${SRC_BIN}" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
fi
echo "✓ Installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"

# 9. Install Shell Completions (bash, zsh, fish)
if [ -d "${TMP_DIR}/completions" ]; then
    cp -r "${TMP_DIR}/completions/"* "${COMPLETIONS_DIR}/" 2>/dev/null || true
else
    "${INSTALL_DIR}/${BINARY_NAME}" completion bash > "${COMPLETIONS_DIR}/boxr.bash" 2>/dev/null || true
    "${INSTALL_DIR}/${BINARY_NAME}" completion zsh > "${COMPLETIONS_DIR}/_boxr" 2>/dev/null || true
    "${INSTALL_DIR}/${BINARY_NAME}" completion fish > "${COMPLETIONS_DIR}/boxr.fish" 2>/dev/null || true
fi

# Auto-configure fish completions if fish configuration exists
if [ -d "${HOME}/.config/fish" ]; then
    mkdir -p "${HOME}/.config/fish/completions"
    cp "${COMPLETIONS_DIR}/boxr.fish" "${HOME}/.config/fish/completions/boxr.fish" 2>/dev/null || true
fi
echo "✓ Installed shell completions in ${COMPLETIONS_DIR}"

# 10. Update Shell Profile PATH if needed
PATH_EXPORT="export PATH=\"${INSTALL_DIR}:\$PATH\""
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*)
        # Already present in environment PATH
        ;;
    *)
        UPDATED_RC=0
        for RC_FILE in "${HOME}/.zshrc" "${HOME}/.bashrc" "${HOME}/.profile"; do
            if [ -f "${RC_FILE}" ]; then
                if ! grep -q "${INSTALL_DIR}" "${RC_FILE}" 2>/dev/null; then
                    printf "\n# boxr container engine\n%s\n" "${PATH_EXPORT}" >> "${RC_FILE}"
                    echo "✓ Added ${INSTALL_DIR} to ${RC_FILE}"
                    UPDATED_RC=1
                fi
            fi
        done
        if [ "${UPDATED_RC}" -eq 0 ]; then
            SHELL_NAME="$(basename "${SHELL:-bash}")"
            case "${SHELL_NAME}" in
                zsh) DEFAULT_RC="${HOME}/.zshrc" ;;
                bash) DEFAULT_RC="${HOME}/.bashrc" ;;
                *) DEFAULT_RC="${HOME}/.profile" ;;
            esac
            printf "\n# boxr container engine\n%s\n" "${PATH_EXPORT}" >> "${DEFAULT_RC}"
            echo "✓ Added ${INSTALL_DIR} to ${DEFAULT_RC}"
        fi
        ;;
esac

echo ""
echo "=========================================="
echo "      boxr installation complete! 🎉      "
echo "=========================================="
echo ""
echo "To get started right away in this shell:"
echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
echo ""
echo "Verify installation:"
echo "  boxr --version"
echo ""
echo "(Optional) Docker Drop-in Alias:"
echo "  If you want 'docker' commands to transparently use boxr:"
echo "    boxr alias --install"
echo ""
echo "Run your first container:"
echo "  boxr run hello-world"
echo ""
