/*
 * Copyright (c) 2012-2022 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.impl;

import android.os.ParcelFileDescriptor;

import de.blinkt.openvpn.core.TrafficHistory;

public interface IServiceState {

    ParcelFileDescriptor registerStatusCallback(IStateCallbacks cb);

    void unregisterStatusCallback(IStateCallbacks cb);

    String getLastConnectedVPN();

    void setCachedPassword(String uuid, int type, String password);

    TrafficHistory getTrafficHistory();

}
