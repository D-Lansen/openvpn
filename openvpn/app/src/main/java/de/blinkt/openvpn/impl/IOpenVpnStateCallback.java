/*
 * Copyright (c) 2012-2022 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.impl;

import android.os.IInterface;

public interface IOpenVpnStateCallback extends IInterface {
    void newStatus(String uuid, String state, String message, String level);
}
