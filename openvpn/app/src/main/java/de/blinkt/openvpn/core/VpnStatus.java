package de.blinkt.openvpn.core;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.FormatFlagsConversionMismatchException;
import java.util.Locale;
import java.util.UnknownFormatConversionException;
import java.util.Vector;

import de.blinkt.openvpn.R;

public class VpnStatus {
    private static ConnectionStatus mLastLevel = ConnectionStatus.LEVEL_NOTCONNECTED;

    static {
        apiInformation();
    }

    private static void apiInformation() {
        String nativeAPI;
        try {
            nativeAPI = NativeUtils.getNativeAPI();
        } catch (UnsatisfiedLinkError | NoClassDefFoundError ignore) {
            nativeAPI = "error";
        }

        logInfo(R.string.mobile_info, Build.MODEL, Build.BOARD, Build.BRAND, Build.VERSION.SDK_INT,
                nativeAPI, Build.VERSION.RELEASE, Build.ID, Build.FINGERPRINT, "", "");
    }

    private static int getLocalizedState(String state) {
        switch (state) {
            case "CONNECTING":
                return R.string.state_connecting;
            case "WAIT":
                return R.string.state_wait;
            case "AUTH":
                return R.string.state_auth;
            case "GET_CONFIG":
                return R.string.state_get_config;
            case "ASSIGN_IP":
                return R.string.state_assign_ip;
            case "ADD_ROUTES":
                return R.string.state_add_routes;
            case "CONNECTED":
                return R.string.state_connected;
            case "DISCONNECTED":
                return R.string.state_disconnected;
            case "RECONNECTING":
                return R.string.state_reconnecting;
            case "EXITING":
                return R.string.state_exiting;
            case "RESOLVE":
                return R.string.state_resolve;
            case "TCP_CONNECT":
                return R.string.state_tcp_connect;
            case "AUTH_PENDING":
                return R.string.state_auth_pending;
            default:
                return R.string.unknown_state;
        }
    }

    public static void updateStatePause(OpenVPNManagement.pauseReason pauseReason) {
        switch (pauseReason) {
            case noNetwork:
                VpnStatus.updateStateString("NONETWORK", "", R.string.state_nonetwork, ConnectionStatus.LEVEL_NONETWORK);
                break;
            case screenOff:
                VpnStatus.updateStateString("SCREENOFF", "", R.string.state_screenoff, ConnectionStatus.LEVEL_VPNPAUSED);
                break;
            case userPause:
                VpnStatus.updateStateString("USERPAUSE", "", R.string.state_userpause, ConnectionStatus.LEVEL_VPNPAUSED);
                break;
        }
    }

    private static ConnectionStatus getLevel(String state) {
        String[] noreplyet = {"CONNECTING", "WAIT", "RECONNECTING", "RESOLVE", "TCP_CONNECT"};
        String[] reply = {"AUTH", "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES", "AUTH_PENDING"};
        String[] connected = {"CONNECTED"};
        String[] notconnected = {"DISCONNECTED", "EXITING"};

        for (String x : noreplyet)
            if (state.equals(x))
                return ConnectionStatus.LEVEL_CONNECTING_NO_SERVER_REPLY_YET;

        for (String x : reply)
            if (state.equals(x))
                return ConnectionStatus.LEVEL_CONNECTING_SERVER_REPLIED;

        for (String x : connected)
            if (state.equals(x))
                return ConnectionStatus.LEVEL_CONNECTED;

        for (String x : notconnected)
            if (state.equals(x))
                return ConnectionStatus.LEVEL_NOTCONNECTED;

        return ConnectionStatus.UNKNOWN_LEVEL;

    }

    static void updateStateString(String state, String msg) {
        // We want to skip announcing that we are trying to get the configuration since
        // this is just polling until the user input has finished.be
        if (mLastLevel == ConnectionStatus.LEVEL_WAITING_FOR_USER_INPUT && state.equals("GET_CONFIG"))
            return;
        int rid = getLocalizedState(state);
        ConnectionStatus level = getLevel(state);
        updateStateString(state, msg, rid, level);
    }

    public synchronized static void updateStateString(String state, String msg, int resid, ConnectionStatus level) {
        if (mLastLevel == ConnectionStatus.LEVEL_CONNECTED &&
                (state.equals("WAIT") || state.equals("AUTH"))) {
            logDebug(String.format("Ignoring OpenVPN Status in CONNECTED state (%s->%s): %s", state, level.toString(), msg));
            return;
        }
        mLastLevel = level;
    }

    public static String getLogStr(String mMessage, int mResourceId, Object[] mArgs) {
        try {
            if (mMessage != null) {
                return mMessage;
            } else {
                String str = String.format(Locale.ENGLISH, "resid %d ", mResourceId);
                if (mArgs != null)
                    str += join("|", mArgs);
                return str;
            }
        } catch (UnknownFormatConversionException | FormatFlagsConversionMismatchException e) {
            return "";
        }
    }

    public static String join(CharSequence delimiter, Object[] tokens) {
        StringBuilder sb = new StringBuilder();
        boolean firstTime = true;
        for (Object token : tokens) {
            if (firstTime) {
                firstTime = false;
            } else {
                sb.append(delimiter);
            }
            sb.append(token);
        }
        return sb.toString();
    }

    public static void logInfo(String message) {
        Log.i("Log", getLogStr(message, 0, null));
    }

    public static void logInfo(int resourceId, Object... args) {
        Log.i("Log", getLogStr(null, resourceId, args));
    }

    public static void logInfo(String message, int resourceId, Object... args) {
        Log.i("Log", getLogStr(message, resourceId, args));
    }

    public static void logDebug(String message) {
        Log.d("Log", getLogStr(message, 0, null));
    }

    public static void logDebug(int resourceId, Object... args) {
        Log.d("Log", getLogStr(null, resourceId, args));
    }

    public static void logDebug(String message, int resourceId, Object... args) {
        Log.d("Log", getLogStr(message, resourceId, args));
    }

    public static void logWarning(int resourceId, Object... args) {
        Log.w("Log", getLogStr(null, resourceId, args));
    }

    public static void logWarning(String msg) {
        Log.w("Log", getLogStr(msg, 0, null));
    }

    public static void logWarning(String msg, int resourceId, Object... args) {
        Log.w("Log", getLogStr(msg, resourceId, args));
    }

    public static void logError(String msg) {
        Log.e("Log", getLogStr(msg, 0, null));
    }

    public static void logError(int resourceId) {
        Log.e("Log", getLogStr(null, resourceId, null));
    }

    public static void logError(int resourceId, Object... args) {
        Log.e("Log", getLogStr(null, resourceId, args));
    }

    public static void logError(String msg, int resourceId, Object... args) {
        Log.e("Log", getLogStr(msg, resourceId, args));
    }

    public static void logException(Throwable e) {
        logException(null, e);
    }

    public static void logException(String context, Throwable e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        logError(context, 0, e.getMessage(), sw.toString());
    }

}
