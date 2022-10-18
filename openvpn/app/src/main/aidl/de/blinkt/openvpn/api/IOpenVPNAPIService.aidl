// IOpenVPNAPIService.aidl
package de.blinkt.openvpn.api;

import de.blinkt.openvpn.api.APIVpnProfile;
import de.blinkt.openvpn.api.IOpenVPNStatusCallback; 

import android.content.Intent;
import android.os.ParcelFileDescriptor;

interface IOpenVPNAPIService {

	void startProfile (String profileUUID);
	

	/** start a profile using a config as inline string. Make sure that all needed data is inlined,
	 * e.g., using <ca>...</ca> or <auth-user-pass>...</auth-user-pass>
	 * See the OpenVPN manual page for more on inlining files */
	void startVPN (in String inlineconfig);


	/* Disconnect the VPN */
    void disconnect();

    /* Pause the VPN (same as using the pause feature in the notifcation bar) */
    void pause();

    /* Resume the VPN (same as using the pause feature in the notifcation bar) */
    void resume();
    
    /**
      * Registers to receive OpenVPN Status Updates
      */
    void registerStatusCallback(in IOpenVPNStatusCallback cb);
    
    /**
     * Remove a previously registered callback interface.
     */
    void unregisterStatusCallback(in IOpenVPNStatusCallback cb);

	/** Remove a profile by UUID */
//	void removeProfile (in String profileUUID);

	/** Request a socket to be protected as a VPN socket would be. Useful for creating
	  * a helper socket for an app controlling OpenVPN
	  * Before calling this function you should make sure OpenVPN for Android may actually
	  * this function by checking if prepareVPNService returns null; */
	boolean protectSocket(in ParcelFileDescriptor fd);

}