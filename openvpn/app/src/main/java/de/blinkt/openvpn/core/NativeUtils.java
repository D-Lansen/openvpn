package de.blinkt.openvpn.core;

public class NativeUtils {

    static {
        System.loadLibrary("openvpn");
    }

    private static native String getJNIAPI();

    public static String getNativeAPI() {
        return getJNIAPI();
    }

}