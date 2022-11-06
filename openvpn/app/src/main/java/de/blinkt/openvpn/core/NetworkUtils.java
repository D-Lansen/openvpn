package de.blinkt.openvpn.core;

import android.annotation.SuppressLint;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.provider.Settings;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.Vector;

public class NetworkUtils {

    public static Vector<String> getLocalNetworks(Context c, boolean ipv6) {
        Vector<String> nets = new Vector<>();
        ConnectivityManager conn = (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);

        Network[] networks = conn.getAllNetworks();
        for (Network network : networks) {

            LinkProperties li = conn.getLinkProperties(network);

            NetworkCapabilities nc = conn.getNetworkCapabilities(network);

            // Ignore network if it has no capabilities
            if (nc == null)
                continue;

            // Skip VPN networks like ourselves
            if (nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
                continue;

            // Also skip mobile networks
            if (nc.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))
                continue;


            for (LinkAddress la : li.getLinkAddresses()) {
                if ((la.getAddress() instanceof Inet4Address && !ipv6) ||
                        (la.getAddress() instanceof Inet6Address && ipv6))
                    nets.add(la.toString());
            }
        }

        return nets;
    }

    @SuppressLint("HardwareIds")
    public static String getFakeMacAddrFromSAAID(Context c) {
        char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

        String saaId = Settings.Secure.getString(c.getContentResolver(),
                Settings.Secure.ANDROID_ID);

        if (saaId == null)
            return null;

        StringBuilder ret = new StringBuilder();
        if (saaId.length() >= 6) {
            byte[] sb = saaId.getBytes();
            for (int b = 0; b <= 6; b++) {
                if (b != 0)
                    ret.append(":");
                int v = sb[b] & 0xFF;
                ret.append(HEX_ARRAY[v >>> 4]);
                ret.append(HEX_ARRAY[v & 0x0F]);
            }
        }
        return ret.toString();
    }

}