# 解构2.5.5 手动安装
# 修改为2.6.2安装

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi
# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001
if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

echo "OpenVPN installation is ready to begin"

openvpn_dir="/home/lichen/Desktop/github/openvpn/server/cmake-build-debug/"
client="client"
base_dir=$(dirname $0)

conf_dir="${base_dir}/bin/server/" 
if [[ ! -e $conf_dir ]]; then 
	mkdir -p $conf_dir 
fi

rsa_path="${base_dir}/bin/easy-rsa/"
echo "rsa_path: "${rsa_path}

if [[ ! -e $rsa_path ]]; then
	echo "Download EasyRSA-3.1.0 from github"
	easy_rsa_url="https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz"
	mkdir -p $rsa_path
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C $rsa_path --strip-components 1
fi

if [[ ! -e $conf_dir/server.key ]]; then
	echo "Create the PKI, set up the CA and the server and client certificates"
	cd ${rsa_path}
	rm -rf ${rsa_path}/pki
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full $client nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem $conf_dir
	rm -rf ${rsa_path}/pki
fi

${openvpn_dir}openvpn --version

# Create the DH parameters file using the predefined ffdhe2048 group
echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > ${conf_dir}/dh.pem

# Generate server.conf
echo "local 192.168.0.100
port 11194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
# tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > ${conf_dir}/server.conf
echo 'push "redirect-gateway def1 bypass-dhcp"' >> ${conf_dir}/server.conf
echo 'ifconfig-pool-persist ipp.txt' >> ${conf_dir}/server.conf
echo 'push "dhcp-option DNS 192.168.0.1"' >> ${conf_dir}/server.conf
echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
verb 3
crl-verify crl.pem" >> ${conf_dir}/server.conf
echo "explicit-exit-notify" >> ${conf_dir}/server.conf


# Enable net.ipv4.ip_forward for the system
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
# Enable without waiting for a reboot or service restart
echo 1 > /proc/sys/net/ipv4/ip_forward

# Create a service to set up persistent iptables rules
if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
	iptables_path=$(command -v iptables-legacy)
else
	iptables_path=$(command -v iptables)
fi
echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
systemctl enable --now openvpn-iptables.service


