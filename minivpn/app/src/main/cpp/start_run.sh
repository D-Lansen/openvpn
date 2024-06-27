#!/bin/sh

base_dir=$(dirname "$0")

server_dir="${base_dir}/bin/server/"
if [ ! -e "$server_dir" ]; then
	mkdir -p "$server_dir"
fi
cd "${server_dir}"

openvpn_dir="${base_dir}/cmake-build-linux"

openvpn_path="${server_dir}/openvpn"
if [ -e "$openvpn_path" ]; then
  sudo "$openvpn_path" --config server.conf
fi
