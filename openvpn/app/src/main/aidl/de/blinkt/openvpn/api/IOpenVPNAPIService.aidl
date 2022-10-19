// IOpenVPNAPIService.aidl
package de.blinkt.openvpn.api;

import android.content.Intent;
import android.os.ParcelFileDescriptor;

interface IOpenVPNAPIService {

	void startProfile (String profileUUID);

	void startVPN (in String inlineconfig);

	boolean protectSocket(in ParcelFileDescriptor fd);

}