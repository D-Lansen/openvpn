#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}


//#  sudo vi /usr/lib/systemd/system/openvpn-client@.service
//#  sudo vi /usr/lib/systemd/system/openvpn-server@.service
//#  sudo vi /usr/lib/systemd/system/openvpn@.service
//
//#  sudo systemctl stop openvpn-server@server.service
//#  sudo systemctl start openvpn-server@server.service
//#  sudo systemctl status openvpn-server@server.service
//#  sudo systemctl enable openvpn-server@server.service
//#  systemctl daemon-reload