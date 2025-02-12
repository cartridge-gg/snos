#!/usr/bin/env bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
REPO_ROOT=$( dirname -- $SCRIPT_DIR )
DOJO_IMAGE=ghcr.io/dojoengine/dojo:preview--f0c1e0b

# Create directory for katana db
mkdir -p $REPO_ROOT/katana_db

# Runs katana in the background
$SUDO docker run -d --name katana \
  -v "$REPO_ROOT/tests/fixtures/chain-config:/chain-config" \
  -v "$REPO_ROOT/katana_db:/katana-db" \
   $DOJO_IMAGE \
  katana --chain /chain-config --db-dir /katana-db

# Wait kor katana to start
sleep 5

SOZO_MIGRATOR_ADDRESS=0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d
SOZO_MIGRATOR_PRIVATE_KEY=0x7230b49615d175307d580c33d6fda61fc7b9aec91df0f5c1a5ebe3b8cbfee02

# bulid and migrate project
$SUDO docker run --rm \
  --network container:katana \
  -v "$REPO_ROOT/examples/spawn-and-move:/workspace" \
  -w /workspace \
  $DOJO_IMAGE \
  sh -c 'sozo build && sozo migrate --account-address $SOZO_MIGRATOR_ADDRESS --private-key $SOZO_MIGRATOR_PRIVATE_KEY'

# Clean up - stop the katana container
$SUDO docker stop katana
$SUDO docker rm katana
