#!/bin/bash

# Build script for kerbrute
# Builds for Linux arm64, Linux amd64 (x86_64), Darwin (macOS), and Windows

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
TARGET_DIR="./dist"
PACKAGE_NAME="github.com/ropnop/kerbrute"
BINARY_NAME="kerbrute"

# Get version info
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date +%m/%d/%y)
GOVERSION=$(go version | cut -d " " -f 3)

if [ -z "$VERSION" ]; then
    VERSION="dev"
fi

# Build flags
LDFLAGS="-X ${PACKAGE_NAME}/util.GitCommit=${COMMIT} \
-X ${PACKAGE_NAME}/util.BuildDate=${DATE} \
-X ${PACKAGE_NAME}/util.GoVersion=${GOVERSION} \
-X ${PACKAGE_NAME}/util.Version=${VERSION}"

# Create output directory
mkdir -p "${TARGET_DIR}"

echo -e "${GREEN}Building kerbrute for multiple platforms...${NC}"
echo -e "Version: ${VERSION}"
echo -e "Commit: ${COMMIT}"
echo -e "Go Version: ${GOVERSION}"
echo ""

# Function to build for a specific platform
build_platform() {
    local GOOS=$1
    local GOARCH=$2
    local EXT=$3
    local PLATFORM_NAME=$4
    
    echo -e "${YELLOW}Building for ${PLATFORM_NAME} (${GOOS}/${GOARCH})...${NC}"
    
    GOOS=${GOOS} GOARCH=${GOARCH} go build -a -ldflags "${LDFLAGS}" \
        -o "${TARGET_DIR}/${BINARY_NAME}_${GOOS}_${GOARCH}${EXT}" || {
        echo -e "${RED}Failed to build for ${PLATFORM_NAME}${NC}"
        exit 1
    }
    
    echo -e "${GREEN}✓ Built: ${TARGET_DIR}/${BINARY_NAME}_${GOOS}_${GOARCH}${EXT}${NC}"
}

# Build for Linux AMD64 (x86_64)
build_platform "linux" "amd64" "" "Linux AMD64"

# Build for Linux ARM64
build_platform "linux" "arm64" "" "Linux ARM64"

# Build for Darwin (macOS) AMD64
build_platform "darwin" "amd64" "" "Darwin AMD64"

# Build for Darwin (macOS) ARM64 (Apple Silicon)
build_platform "darwin" "arm64" "" "Darwin ARM64"

# Build for Windows AMD64
build_platform "windows" "amd64" ".exe" "Windows AMD64"

echo ""
echo -e "${GREEN}Build completed successfully!${NC}"
echo -e "Binaries are located in: ${TARGET_DIR}/"
echo ""
echo "Built binaries:"
ls -lh "${TARGET_DIR}" | grep "${BINARY_NAME}" || echo "No binaries found"

