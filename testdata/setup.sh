#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
pushd "${SCRIPT_DIR}"

ARCHIVE_URL="https://git.gammaspectra.live/P2Pool/p2pool/raw/commit/"

# Pre-v2 p2pool hardfork
OLD_TESTS_COMMIT_ID=b9eb66e2b3e02a5ec358ff8a0c5169a5606d9fde

function download_old_test() {
    if [ -f "./old_${1}" ]; then
      return
    fi
    curl --progress-bar --output "./old_${1}" "${ARCHIVE_URL}${OLD_TESTS_COMMIT_ID}/tests/src/${1}"
}

# Post-v2 p2pool hardfork
TESTS_COMMIT_ID=f455ce398c20137a92a67b062c6311580939abea

function download_test() {
    if [ -f "./${1}" ]; then
      return
    fi
    curl --progress-bar --output "./${1}" "${ARCHIVE_URL}${TESTS_COMMIT_ID}/tests/src/${1}"
}

download_test block.dat
download_test crypto_tests.txt
download_test sidechain_dump.dat.gz
download_test sidechain_dump_mini.dat.gz

download_old_test mainnet_test2_block.dat
download_old_test sidechain_dump.dat
download_old_test sidechain_dump_mini.dat

sha256sum -c testdata.sha256