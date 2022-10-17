/*
 * Copyright (c) 2012-2022 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.impl;

import android.content.Intent;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;

import java.util.List;

import de.blinkt.openvpn.api.APIVpnProfile;

public interface IOpenVpnApiService {

    List<APIVpnProfile> getProfiles();

    void startProfile (String profileUUID);

    boolean addVPNProfile (String name, String config);

    void startVPN (String inlineConfig);

    Intent prepare (String packageName);

    Intent prepareVPNService ();

    void disconnect() throws RemoteException;

    void pause() throws RemoteException;

    void resume() throws RemoteException;

    void registerStatusCallback(IOpenVpnStateCallback cb);

    void unregisterStatusCallback(IOpenVpnStateCallback cb);

    void removeProfile (String profileUUID);

    boolean protectSocket(ParcelFileDescriptor fd);

    APIVpnProfile addNewVPNProfile (String name, boolean userEditable, String config);

    void startVpnWithExtras(String inlineConfig, Bundle extras);
}
