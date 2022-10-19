/*
 * Copyright (c) 2012-2022 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.impl;

public interface IOpenVpnServiceInternal {

    boolean protect(int fd);

    void userPause(boolean b);

    boolean stopVPN(boolean replaceConnection);

    void challengeResponse(String response);

}
