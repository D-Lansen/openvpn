package world.daochen.minivpn;


import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.NetworkInfo.State;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import java.util.Objects;

public class DeviceStateReceiver extends BroadcastReceiver implements OpenVpnManagementThread.PausedStateCallback {
    private static final String TAG = "DeviceStateReceiver";
    private final Handler mDisconnectHandler;

    private final OpenVpnManagementThread mManagement;

    connectState network = connectState.DISCONNECTED;
    connectState screen = connectState.SHOULDBECONNECTED;
    connectState userPause = connectState.SHOULDBECONNECTED;

    private String lastStateMsg = null;
    private final Runnable mDelayDisconnectRunnable = new Runnable() {
        @Override
        public void run() {
            if (!(network == connectState.PENDINGDISCONNECT))
                return;
            network = connectState.DISCONNECTED;
            // Set screen state to be disconnected if disconnect pending
            if (screen == connectState.PENDINGDISCONNECT)
                screen = connectState.DISCONNECTED;
            mManagement.pause();
        }
    };
    private NetworkInfo lastConnectedNetwork;

    @Override
    public boolean shouldBeRunning() {
        return shouldBeConnected();
    }

    private enum connectState {
        SHOULDBECONNECTED,
        PENDINGDISCONNECT,
        DISCONNECTED
    }

    public void userPause(boolean pause) {
        if (pause) {
            userPause = connectState.DISCONNECTED;
            // Check if we should disconnect
            mManagement.pause();
        } else {
            boolean wereConnected = shouldBeConnected();
            userPause = connectState.SHOULDBECONNECTED;
            if (shouldBeConnected() && !wereConnected)
                mManagement.resume();
            else
                // Update the reason why we currently paused
                mManagement.pause();
        }
    }

    public DeviceStateReceiver(OpenVpnManagementThread management) {
        super();
        mManagement = management;
        mManagement.setPauseCallback(this);
        mDisconnectHandler = new Handler(Looper.getMainLooper());
    }


    @Override
    public void onReceive(Context context, Intent intent) {
        if (ConnectivityManager.CONNECTIVITY_ACTION.equals(intent.getAction())) {
            networkStateChange(context);
        } else if (Intent.ACTION_SCREEN_OFF.equals(intent.getAction())) {
            Log.e("DeviceStateReceiver", "onReceive.ACTION_SCREEN_OFF");
        } else if (Intent.ACTION_SCREEN_ON.equals(intent.getAction())) {
            // Network was disabled because screen off
            boolean connected = shouldBeConnected();
            screen = connectState.SHOULDBECONNECTED;
            /* We should connect now, cancel any outstanding disconnect timer */
            mDisconnectHandler.removeCallbacks(mDelayDisconnectRunnable);
            /* should be connected has changed because the screen is on now, connect the VPN */
            if (shouldBeConnected() != connected)
                mManagement.resume();
            else if (!shouldBeConnected())
                /*Update the reason why we are still paused */
                mManagement.pause();
        }
    }

    public static boolean equalsObj(Object a, Object b) {
        return Objects.equals(a, b);
    }

    public void networkStateChange(Context context) {
        NetworkInfo networkInfo = getCurrentNetworkInfo(context);
        String netStateString;
        if (networkInfo == null) {
            netStateString = "not connected";
        } else {
            String subtype = networkInfo.getSubtypeName();
            if (subtype == null)
                subtype = "";
            String extrainfo = networkInfo.getExtraInfo();
            if (extrainfo == null)
                extrainfo = "";

            netStateString = String.format("%2$s %4$s to %1$s %3$s", networkInfo.getTypeName(),
                    networkInfo.getDetailedState(), extrainfo, subtype);
        }

        if (networkInfo != null && networkInfo.getState() == State.CONNECTED) {

            boolean pendingDisconnect = (network == connectState.PENDINGDISCONNECT);
            network = connectState.SHOULDBECONNECTED;

            boolean sameNetwork = lastConnectedNetwork != null
                    && lastConnectedNetwork.getType() == networkInfo.getType()
                    && equalsObj(lastConnectedNetwork.getExtraInfo(), networkInfo.getExtraInfo());

            /* Same network, connection still 'established' */
            if (pendingDisconnect && sameNetwork) {
                mDisconnectHandler.removeCallbacks(mDelayDisconnectRunnable);
                mManagement.networkChange(true);
            } else {
                /* Different network or connection not established anymore */

                if (screen == connectState.PENDINGDISCONNECT)
                    screen = connectState.DISCONNECTED;

                if (shouldBeConnected()) {
                    mDisconnectHandler.removeCallbacks(mDelayDisconnectRunnable);

                    if (pendingDisconnect || !sameNetwork)
                        mManagement.networkChange(false);
                    else
                        mManagement.resume();
                }

                lastConnectedNetwork = networkInfo;
            }
        } else if (networkInfo == null) {
            network = connectState.PENDINGDISCONNECT;
            // Time to wait after network disconnect to pause the VPN
            int DISCONNECT_WAIT = 20;
            mDisconnectHandler.postDelayed(mDelayDisconnectRunnable, DISCONNECT_WAIT * 1000);
        }

        if (!netStateString.equals(lastStateMsg))
            Log.i(TAG, "Network Status: " + netStateString);
        Log.d(TAG, "Debug state info: "+netStateString+", network: "+network );
        lastStateMsg = netStateString;
    }

    public boolean isUserPaused() {
        return userPause == connectState.DISCONNECTED;
    }

    private boolean shouldBeConnected() {
        return (screen == connectState.SHOULDBECONNECTED && userPause == connectState.SHOULDBECONNECTED &&
                network == connectState.SHOULDBECONNECTED);
    }

    private NetworkInfo getCurrentNetworkInfo(Context context) {
        ConnectivityManager conn = (ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);

        return conn.getActiveNetworkInfo();
    }
}
