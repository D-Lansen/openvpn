# #!/bin/s


# Detect OS
if [ "$(uname)" = "Darwin" ]; then
	os="mac"
	group_name="nobody"
	local_ip=$(ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:")
	public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
elif grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	group_name="nogroup"
	local_ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n 1p)
	public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
		echo "Ubuntu 18.04 or higher is required to use this installer. This version of Ubuntu is too old."
	exit
	fi
else
	echo "This installer supported distros are ubuntu and macos"
	exit
fi

echo "OpenVPN installation is ready to begin for ${os}"

client="client"
base_dir=$(dirname "$0")

openvpn_dir="${base_dir}/cmake-build-linux/"
if [[ ! -e "$openvpn_dir" ]]; then
	mkdir -p "$openvpn_dir"
fi

conf_dir="${base_dir}/bin/server/"
if [[ ! -e "$conf_dir" ]]; then
	mkdir -p "$conf_dir"
fi

echo "local_ip:""${local_ip}"
echo "public_ip:""${public_ip}"

echo "" >> "${conf_dir}/ipp.txt"

# Generate server.conf
echo "local $local_ip
port 11194
proto tcp
dev tun
topology subnet
server 10.8.0.0 255.255.255.0" > "${conf_dir}/server.conf"
echo 'push "redirect-gateway def1 bypass-dhcp"' >> "${conf_dir}/server.conf"
echo 'ifconfig-pool-persist ipp.txt' >> "${conf_dir}/server.conf"

# Obtain the resolvers from resolv.conf and use them for OpenVPN
if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
	resolv_conf="/etc/resolv.conf"
else
	resolv_conf="/run/systemd/resolve/resolv.conf"
fi
grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
	echo "push \"dhcp-option DNS $line\"" >> "${conf_dir}/server.conf"
done

echo "keepalive 10 120
user nobody
group $group_name
persist-key
persist-tun
verb 3" >> "${conf_dir}"/server.conf
echo "explicit-exit-notify" >> "${conf_dir}"/server.conf

# Generates the custom client.ovpn
if [ -e "$openvpn_dir/openvpn" ]; then
	{
	echo "client
dev tun
proto tcp
remote $public_ip 11194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verb 3"
	} > "$conf_dir"/"$client".ovpn
fi


if [ "$os" == "ubuntu" ]; then
	chmod +777 -R "${base_dir}/bin/"
	chmod +777 -R "${openvpn_dir}"
fi


# Enable net.ipv4.ip_forward for the system
echo 'net.ipv4.ip_forward=1'
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
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $local_ip
ExecStart=$iptables_path -I INPUT -p tcp --dport 11194 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $local_ip
ExecStop=$iptables_path -D INPUT -p tcp --dport 11194 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service

# Enable and start the OpenVPN service
systemctl enable --now openvpn-iptables.service
systemctl start openvpn-iptables.service


