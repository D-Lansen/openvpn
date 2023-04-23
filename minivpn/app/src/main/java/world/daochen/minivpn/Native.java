package world.daochen.minivpn;

public class Native {
    private static final String OVPNEXE = "ovpnexec";
    public static String getOvpnexe(){
        return "lib"+OVPNEXE+".so";
    }

    static {
        System.loadLibrary(OVPNEXE);
    }
    private static native String getAbi();

    private static native String stringFromJNI();

    public static String getStringFromJNI(){
        return stringFromJNI();
    }

    public static String getNativeAbi(){
        return getAbi();
    }
}