package de.blinkt.openvpn.core;

public class NativeUtils {

//    static {
//        System.loadLibrary("ovpnexec");
//    }

    private static native String getJNIAPI();

    public static String getNativeAPI() {
        return "arm64-v8a";
        //return getJNIAPI();
    }

}