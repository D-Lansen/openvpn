/*
 * Copyright (c) 2012-2016 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.api;

import android.annotation.TargetApi;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.os.RemoteCallbackList;
import android.os.RemoteException;

import java.io.IOException;
import java.io.StringReader;
import java.lang.ref.WeakReference;
import java.util.LinkedList;
import java.util.List;

import de.blinkt.openvpn.R;
import de.blinkt.openvpn.VpnProfile;
import de.blinkt.openvpn.core.ConfigParser;
import de.blinkt.openvpn.core.ConfigParser.ConfigParseError;
import de.blinkt.openvpn.core.ConnectionStatus;
import de.blinkt.openvpn.core.IOpenVPNServiceInternal;
import de.blinkt.openvpn.core.OpenVPNService;
import de.blinkt.openvpn.core.ProfileManager;
import de.blinkt.openvpn.core.VPNLaunchHelper;
import de.blinkt.openvpn.core.VpnStatus;
import de.blinkt.openvpn.core.VpnStatus.StateListener;

public class ExternalOpenVPNService extends Service implements StateListener {

    private static final int SEND_TOALL = 0;

    private static final String EXTRA_INLINE_PROFILE_ALLOW_VPN_BYPASS = "de.blinkt.openvpn.api.ALLOW_VPN_BYPASS";

    private static final String PACKAGE_NAME = "de.blinkt.openvpn";

    final RemoteCallbackList<IOpenVPNStatusCallback> mCallbacks = new RemoteCallbackList<>();

    private IOpenVPNServiceInternal mService;

    private ServiceConnection mConnection = new ServiceConnection() {

        @Override
        public void onServiceConnected(ComponentName className, IBinder service) {
            mService = IOpenVPNServiceInternal.Stub.asInterface(service);
        }

        @Override
        public void onServiceDisconnected(ComponentName arg0) {
            mService = null;
        }

    };

    private BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent != null && Intent.ACTION_UNINSTALL_PACKAGE.equals(intent.getAction())) {
                // Check if the running config is temporary and installed by the app being uninstalled
                VpnProfile vp = ProfileManager.getLastConnectedVpn();
                if (ProfileManager.isTempProfile()) {
                    if (intent.getPackage().equals(vp.mProfileCreator)) {
                        if (mService != null)
                            try {
                                mService.stopVPN(false);
                            } catch (RemoteException e) {
                                e.printStackTrace();
                            }
                    }
                }
            }
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        VpnStatus.addStateListener(this);

        Intent intent = new Intent(getBaseContext(), OpenVPNService.class);
        intent.setAction(OpenVPNService.START_SERVICE);

        bindService(intent, mConnection, Context.BIND_AUTO_CREATE);
        mHandler.setService(this);
        IntentFilter uninstallBroadcast = new IntentFilter(Intent.ACTION_PACKAGE_REMOVED);
        registerReceiver(mBroadcastReceiver, uninstallBroadcast);

    }

    private final IOpenVPNAPIService.Stub mBinder = new IOpenVPNAPIService.Stub() {

        @Override
        public void startProfile(String profileUUID) throws RemoteException {
            VpnProfile vp = ProfileManager.get(getBaseContext(), profileUUID);
            if (vp.checkProfile(getApplicationContext()) != R.string.no_error_found)
                throw new RemoteException(getString(vp.checkProfile(getApplicationContext())));
            VPNLaunchHelper.startOpenVpn(vp, getBaseContext());
        }

        @Override
        public void startVPN(String inlineConfig) throws RemoteException {

            ConfigParser cp = new ConfigParser();
            try {
                cp.parseConfig(new StringReader(inlineConfig));
                VpnProfile vp = cp.convertProfile();
                vp.mName = "Remote APP VPN";
                if (vp.checkProfile(getApplicationContext()) != R.string.no_error_found)
                    throw new RemoteException(getString(vp.checkProfile(getApplicationContext())));

                vp.mProfileCreator = PACKAGE_NAME;

                ProfileManager.setTemporaryProfile(ExternalOpenVPNService.this, vp);

                VPNLaunchHelper.startOpenVpn(vp, getBaseContext());

            } catch (IOException | ConfigParseError e) {
                throw new RemoteException(e.getMessage());
            }
        }

        @Override
        public boolean protectSocket(ParcelFileDescriptor pfd) throws RemoteException {
            try {
                boolean success = mService.protect(pfd.getFd());
                pfd.close();
                return success;
            } catch (IOException e) {
                throw new RemoteException(e.getMessage());
            }
        }

        @Override
        public void registerStatusCallback(IOpenVPNStatusCallback cb) throws RemoteException {
            if (cb != null) {
                cb.newStatus(mMostRecentState.vpnUUID, mMostRecentState.state,
                        mMostRecentState.logMessage, mMostRecentState.level.name());
                mCallbacks.register(cb);
            }
        }

        @Override
        public void unregisterStatusCallback(IOpenVPNStatusCallback cb) throws RemoteException {
            if (cb != null)
                mCallbacks.unregister(cb);
        }

        @Override
        public void disconnect() throws RemoteException {
            if (mService != null)
                mService.stopVPN(false);
        }

        @Override
        public void pause() throws RemoteException {
            if (mService != null)
                mService.userPause(true);
        }

        @Override
        public void resume() throws RemoteException {
            if (mService != null)
                mService.userPause(false);
        }
    };


    private UpdateMessage mMostRecentState;

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        mCallbacks.kill();
        unbindService(mConnection);
        VpnStatus.removeStateListener(this);
        unregisterReceiver(mBroadcastReceiver);
    }


    class UpdateMessage {
        public String state;
        public String logMessage;
        public ConnectionStatus level;
        String vpnUUID;

        UpdateMessage(String state, String logMessage, ConnectionStatus level) {
            this.state = state;
            this.logMessage = logMessage;
            this.level = level;
        }
    }

    @Override
    public void updateState(String state, String logmessage, int resid, ConnectionStatus level, Intent intent) {
        mMostRecentState = new UpdateMessage(state, logmessage, level);
        if (ProfileManager.getLastConnectedVpn() != null)
            mMostRecentState.vpnUUID = ProfileManager.getLastConnectedVpn().getUUIDString();

        Message msg = mHandler.obtainMessage(SEND_TOALL, mMostRecentState);
        msg.sendToTarget();

    }

    @Override
    public void setConnectedVPN(String uuid) {

    }

    private static final OpenVPNServiceHandler mHandler = new OpenVPNServiceHandler();


    static class OpenVPNServiceHandler extends Handler {
        WeakReference<ExternalOpenVPNService> service = null;

        private void setService(ExternalOpenVPNService eos) {
            service = new WeakReference<>(eos);
        }

        @Override
        public void handleMessage(Message msg) {

            RemoteCallbackList<IOpenVPNStatusCallback> callbacks;
            switch (msg.what) {
                case SEND_TOALL:
                    if (service == null || service.get() == null)
                        return;

                    callbacks = service.get().mCallbacks;

                    final int N = callbacks.beginBroadcast();
                    for (int i = 0; i < N; i++) {
                        try {
                            sendUpdate(callbacks.getBroadcastItem(i), (UpdateMessage) msg.obj);
                        } catch (RemoteException e) {
                            // The RemoteCallbackList will take care of removing
                            // the dead object for us.
                        }
                    }
                    callbacks.finishBroadcast();
                    break;
            }
        }

        private void sendUpdate(IOpenVPNStatusCallback broadcastItem,
                                UpdateMessage um) throws RemoteException {
            broadcastItem.newStatus(um.vpnUUID, um.state, um.logMessage, um.level.name());
        }
    }

}