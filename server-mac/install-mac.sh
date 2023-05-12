# #!/bin/sh
# sudo vi /usr/lib/systemd/system/openvpn-server@.service
# sudo systemctl stop openvpn-server@server.service
# sudo systemctl start openvpn-server@server.service
# sudo /usr/sbin/openvpn --config '/home/lichen/Desktop/github/openvpn/server/bin/server/server.conf'



# Detect OS
if [ "$(uname)" = "Darwin" ]; then
  os="mac"
else
	echo "This installer seems to be running on an unsupported distribution. Only Supported for MacOS"
	exit
fi

echo "OpenVPN installation is ready to begin for ${os}"

client="client"

base_dir=$(dirname "$0")

openvpn_dir="${base_dir}/cmake-build-debug/"

bin_dir="${base_dir}/bin/"

conf_dir="${base_dir}/bin/server/"
if [[ ! -e "$conf_dir" ]]; then
	mkdir -p "$conf_dir"
fi

rsa_path="${base_dir}/bin/easy-rsa/"
if [[ ! -e "$rsa_path/easyrsa" ]]; then
	echo "Download EasyRSA-3.1.0 from github"
	easy_rsa_url="https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz"
	mkdir -p "$rsa_path"
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C "$rsa_path" --strip-components 1
fi

if [[ ! -e $conf_dir/server.crt ]]; then
	echo "Create the PKI, set up the CA and the server and client certificates"
	cd "${rsa_path}"
	rm -rf "${rsa_path}/pki"
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full $client nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	cp pki/ca.crt pki/private/ca.key "$conf_dir"
	cp pki/issued/server.crt pki/private/server.key "$conf_dir"
	cp pki/issued/${client}.crt pki/private/${client}.key "$conf_dir"
	cp pki/crl.pem "$conf_dir"
	rm -rf "${rsa_path}/pki"
fi

# ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n 1p)


local_ip=$(ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:")
echo "${local_ip}"

public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
echo "${public_ip}"

# Create the DH parameters file using the predefined ffdhe2048 group
echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > "${conf_dir}/dh.pem"

echo "" >> "${conf_dir}/ipp.txt"

"${openvpn_dir}openvpn" --genkey secret "${conf_dir}/tc.key"

# Generate server.conf
echo "local $local_ip
port 11194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > "${conf_dir}/server.conf"
echo 'push "redirect-gateway def1 bypass-dhcp"' >> "${conf_dir}/server.conf"
echo 'ifconfig-pool-persist ipp.txt' >> "${conf_dir}/server.conf"

if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
	resolv_conf="/etc/resolv.conf"
else
	resolv_conf="/run/systemd/resolve/resolv.conf"
fi
# Obtain the resolvers from resolv.conf and use them for OpenVPN
grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
	echo "push \"dhcp-option DNS $line\"" >> "${conf_dir}/server.conf"
done

echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group nobody
persist-key
persist-tun
verb 3
crl-verify crl.pem" >> "${conf_dir}/server.conf"
echo "explicit-exit-notify" >> "${conf_dir}/server.conf"

# Generates the custom client.ovpn
{
echo "client
dev tun
proto udp
remote $public_ip 11194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3"
echo "<ca>"
cat "$conf_dir/ca.crt"
echo "</ca>"
echo "<cert>"
sed -ne '/BEGIN CERTIFICATE/,$ p' "$conf_dir/$client.crt"
echo "</cert>"
echo "<key>"
cat "$conf_dir/$client.key"
echo "</key>"
echo "<tls-crypt>"
sed -ne '/BEGIN OpenVPN Static key/,$ p' "$conf_dir/tc.key"
echo "</tls-crypt>"
} > "$conf_dir"/"$client".ovpn


# Enable net.inet.ip.forwarding for the system
sudo echo 'net.inet.ip.forwarding=1' > /etc/sysctl.conf
# Enable without waiting for a reboot or service restart
sudo sysctl -w net.inet.ip.forwarding=1
sudo sysctl -a | grep "net.inet.ip.forwarding"


# https://blog.51cto.com/swenzhao/1582585
# https://qastack.cn/superuser/468919/prevent-outgoing-traffic-unless-openvpn-connection-is-active-using-pfconf-on-mac-os-x
# https://github.com/essandess/macos-openvpn-server/blob/master/pf.conf
# https://openvpn.net/cloud-docs/owner/networks-and-gateways/networks/enabling-routing-and-nat-on-macos.html

