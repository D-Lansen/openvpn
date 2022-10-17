/*
 * Copyright (c) 2012-2022 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.impl;

import android.content.Intent;

import de.blinkt.openvpn.core.ConnectionStatus;
import de.blinkt.openvpn.core.LogItem;

public interface IStateCallbacks {
    void newLogItem(LogItem item);
    void updateStateString(String state, String msg, int resid, ConnectionStatus level, Intent intent);
    void updateByteCount(long inBytes, long outBytes);
    void connectedVPN(String uuid);
}
