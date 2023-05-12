#!/bin/sh

base_dir=$(dirname "$0")
cd "$base_dir"/bin/server
sudo "$base_dir"/cmake-build-debug/openvpn --config server.conf
