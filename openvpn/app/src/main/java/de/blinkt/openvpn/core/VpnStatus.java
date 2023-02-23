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

    private static final Vector<StateListener> stateListener;

    private static String mLaststatemsg = "";

    private static String mLaststate = "NOPROCESS";

    private static int mLastStateresid = R.string.state_noprocess;

    private static Intent mLastIntent = null;

    public static boolean isVPNActive() {
        return mLastLevel != ConnectionStatus.LEVEL_AUTH_FAILED && !(mLastLevel == ConnectionStatus.LEVEL_NOTCONNECTED);
    }

    public static String getLastCleanLogMessage(Context c) {
        String message = mLaststatemsg;
        switch (mLastLevel) {
            case LEVEL_CONNECTED:
                String[] parts = mLaststatemsg.split(",");
                /*
                   (a) the integer unix date/time,
                   (b) the state name,
                   0 (c) optional descriptive string (used mostly on RECONNECTING
                    and EXITING to show the reason for the disconnect),

                    1 (d) optional TUN/TAP local IPv4 address
                   2 (e) optional address of remote server,
                   3 (f) optional port of remote server,
                   4 (g) optional local address,
                   5 (h) optional local port, and
                   6 (i) optional TUN/TAP local IPv6 address.
*/
                // Return only the assigned IP addresses in the UI
                if (parts.length >= 7)
                    message = String.format(Locale.US, "%s %s", parts[1], parts[6]);
                break;
        }

        while (message.endsWith(","))
            message = message.substring(0, message.length() - 1);

        String status = mLaststate;
        if (status.equals("NOPROCESS"))
            return message;

        if (mLastStateresid == R.string.state_waitconnectretry) {
            return c.getString(R.string.state_waitconnectretry, mLaststatemsg);
        }

        String prefix = c.getString(mLastStateresid);
        if (mLastStateresid == R.string.unknown_state)
            message = status + message;
        if (message.length() > 0)
            prefix += ": ";

        return prefix + message;

    }

    public static String getLastStateId(Context c) {
        String message = mLaststatemsg;
        if (mLastLevel == ConnectionStatus.LEVEL_CONNECTED) {
            String[] parts = mLaststatemsg.split(",");
                /*
                   (a) the integer unix date/time,
                   (b) the state name,
                   0 (c) optional descriptive string (used mostly on RECONNECTING
                    and EXITING to show the reason for the disconnect),

                    1 (d) optional TUN/TAP local IPv4 address
                   2 (e) optional address of remote server,
                   3 (f) optional port of remote server,
                   4 (g) optional local address,
                   5 (h) optional local port, and
                   6 (i) optional TUN/TAP local IPv6 address.
*/
            // Return only the assigned IP addresses in the UI
            if (parts.length >= 7)
                message = String.format(Locale.US, "%s %s", parts[1], parts[6]);
        }

        while (message.endsWith(","))
            message = message.substring(0, message.length() - 1);

        String status = mLaststate;
        if (status.equals("NOPROCESS"))
            return message;

        if (mLastStateresid == R.string.state_waitconnectretry) {
            return c.getString(R.string.state_waitconnectretry, mLaststatemsg);
        }

        String prefix = c.getString(mLastStateresid);
        if (mLastStateresid == R.string.unknown_state)
            message = status + message;
        if (message.length() > 0)
            prefix += ": ";

        return prefix + message;

    }

    public synchronized static void setConnectedVPNProfile(String uuid) {
        for (StateListener sl : stateListener)
            sl.setConnectedVPN(uuid);
    }

    private static ConnectionStatus mLastLevel = ConnectionStatus.LEVEL_NOTCONNECTED;

    static {
        stateListener = new Vector<>();
        apiInformation();
    }

    public interface StateListener {
        void updateState(String state, String logMessage, int localizedResId, ConnectionStatus level, Intent Intent);
        void setConnectedVPN(String uuid);
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

    public synchronized static void addStateListener(StateListener sl) {
        if (!stateListener.contains(sl)) {
            stateListener.add(sl);
            if (mLaststate != null)
                sl.updateState(mLaststate, mLaststatemsg, mLastStateresid, mLastLevel, mLastIntent);
        }
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

    public synchronized static void removeStateListener(StateListener sl) {
        stateListener.remove(sl);
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
        updateStateString(state, msg, resid, level, null);
    }

    public synchronized static void updateStateString(String state, String msg, int resid, ConnectionStatus level, Intent intent) {
        if (mLastLevel == ConnectionStatus.LEVEL_CONNECTED &&
                (state.equals("WAIT") || state.equals("AUTH"))) {
            logDebug(String.format("Ignoring OpenVPN Status in CONNECTED state (%s->%s): %s", state, level.toString(), msg));
            return;
        }

        mLaststate = state;
        mLaststatemsg = msg;
        mLastStateresid = resid;
        mLastLevel = level;
        mLastIntent = intent;

        for (StateListener sl : stateListener) {
            sl.updateState(state, msg, resid, level, intent);
        }
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
