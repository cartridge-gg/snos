#!/usr/bin/env bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
REPO_ROOT=$( dirname -- $SCRIPT_DIR )
DOJO_VERSION=preview--f0c1e0b
# DOJO_VERSION=v1.1.2

echo $SCRIPT_DIR

# Create directory for katana db
mkdir -p $REPO_ROOT/katana_db

$SUDO docker run --rm \
  -v "$REPO_ROOT/bin/prove_block/tests/fixtures/chain-config:/chain-config" \
  ghcr.io/dojoengine/dojo:$DOJO_VERSION \
  katana init --id testchain --settlement-chain sepolia \
  --settlement-account-address 0x04ac0264c73207f9bc7b12801500324be647a8c2fc56964f8e1945ca993006a7 \
  --settlement-private-key 0x1 \
  --settlement-contract 0x5574524482c8eab1a8f3bc0b87ab9f94a9fe1fd7ef1f22f5ff48d8103258c72 \
  --output-path ./chain-config


# Runs katana in the background
$SUDO docker run -d --name katana \
  -v "$REPO_ROOT/bin/prove_block/tests/fixtures/chain-config:/chain-config" \
  -v "$REPO_ROOT/katana_db:/katana-db" \
  ghcr.io/dojoengine/dojo:$DOJO_VERSION \
  katana --chain /chain-config --db-dir /katana-db

# Wait for katana to start
sleep 5

$SUDO docker run --rm \
  -v "$SCRIPT_DIR/entrypoints/spawn_and_move.sh:/scripts:ro" \
  --entrypoint "/scripts" \
  ghcr.io/dojoengine/dojo:$DOJO_VERSION

# Clean up - stop the katana container
$SUDO docker stop katana
$SUDO docker rm katana
