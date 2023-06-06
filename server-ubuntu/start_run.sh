#!/bin/sh

base_dir=$(dirname "$0")

server_dir="${base_dir}/bin/server/"
if [ ! -e $server_dir ]; then
	mkdir -p $server_dir
fi
cd "${server_dir}"

openvpn_dir="${base_dir}/cmake-build-debug/openvpn"
if [ -e ${openvpn_dir} ]; then
  sudo $openvpn_dir --config server.conf
fi
