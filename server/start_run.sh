#!/bin/sh


# /etc/openvpn/server
# /home/lichen/Desktop/github/openvpn/server/bin/server

#sudo systemctl stop openvpn-server@server.service

cd /home/lichen/Desktop/github/openvpn/server/bin/server
sudo /home/lichen/Desktop/github/openvpn/server/cmake-build-debug/openvpn --config server.conf
