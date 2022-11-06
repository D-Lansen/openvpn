package de.blinkt.openvpn.core;

import androidx.annotation.NonNull;

import java.util.Locale;

public class CidrIp {

    public String mIp;
    public int len;

    public CidrIp(String ip, String mask) {
        mIp = ip;
        len = calculateLenFromMask(mask);
    }

    public static int calculateLenFromMask(String mask) {
        long netmask = getLong(mask);

        // Add 33. bit to ensure the loop terminates
        netmask += 1L << 32;

        int lenZeros = 0;
        while ((netmask & 0x1) == 0) {
            lenZeros++;
            netmask = netmask >> 1;
        }
        int len;
        // Check if rest of netmask is only 1s
        if (netmask != (0x1ffffffffL >> lenZeros)) {
            len = 32;
        } else {
            len = 32 - lenZeros;
        }
        return len;
    }

    public CidrIp(String address, int prefix_length) {
        len = prefix_length;
        mIp = address;
    }

    @NonNull
    @Override
    public String toString() {
        return String.format(Locale.ENGLISH, "%s/%d", mIp, len);
    }

    public boolean normalise() {
        long ip = getLong(mIp);

        long newip = ip & (0xffffffffL << (32 - len));
        if (newip != ip) {
            mIp = String.format(Locale.US, "%d.%d.%d.%d", (newip & 0xff000000) >> 24, (newip & 0xff0000) >> 16, (newip & 0xff00) >> 8, newip & 0xff);
            return true;
        } else {
            return false;
        }

    }

    public static long getLong(String ipaddr) {
        String[] ipt = ipaddr.split("\\.");
        long ip = 0;

        ip += Long.parseLong(ipt[0]) << 24;
        ip += Long.parseLong(ipt[1]) << 16;
        ip += Long.parseLong(ipt[2]) << 8;
        ip += Long.parseLong(ipt[3]);

        return ip;
    }

    public long getLong() {
        return getLong(mIp);
    }

}