package world.daochen.minivpn;

import android.content.Intent;
import android.net.VpnService;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class OpenVPNService extends VpnService {
    private static final String TAG = "OpenVPNService";
    private final Object mProcessLock = new Object();
    private Thread mProcessThread = null;

    public class Stub extends Binder {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            switch (code) {
                case 0x001: {
                    data.enforceInterface("startVpn");
                    startVpn(data.readString());
                    reply.writeNoException();
                    return true;
                }
                case 0x010: {
                    data.enforceInterface("userPause");
                    userPause(data.readInt());
                    reply.writeNoException();
                    return true;
                }
                case 0x011: {
                    data.enforceInterface("stopVpn");
                    stopVpn(data.readInt());
                    reply.writeNoException();
                    return true;
                }
            }
            return super.onTransact(code, data, reply, flags);
        }
    }

    private final Stub mBinder = new Stub();

    @Override
    public IBinder onBind(Intent intent) {
        Log.e(TAG, "onBind:");
        return mBinder;
    }

    //todo ovpnName->config
    private void startVpn(String ovpnName) {
        try {
            InputStream conf;
            try {
                conf = this.getAssets().open(ovpnName);
            } catch (IOException e) {
                return;
            }
            BufferedReader br = new BufferedReader(new InputStreamReader(conf));
            StringBuilder config = new StringBuilder();
            String line;
            while (true) {
                line = br.readLine();
                if (line == null) break;
                config.append(line).append("\n");
            }
            br.close();
            conf.close();
            startVpnConfig(config.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

//    private void startVpnConfig(String inlineConfig) {
//        ConfigParser cp = new ConfigParser();
//        try {
//            cp.parseConfig(new StringReader(inlineConfig));
//            VpnProfile vp = cp.convertProfile();
//            vp.mName = "Remote APP VPN";
//            if (vp.checkProfile() != R.string.no_error_found)
//                Log.e("MainActivity", "startVpn.err:" + getString(vp.checkProfile()));
//
//            vp.mProfileCreator = "de.blinkt.openvpn";
//
//            this.mProfile = vp;
//
//            Intent startVPN = vp.getStartServiceIntent(this);
//
//            if (startVPN != null) {
//                this.startService(startVPN);
//            }
//
//        } catch (IOException | ConfigParser.ConfigParseError e) {
//            Log.e("OpenVPNService", "startVpn.err:" + e.getMessage());
//        }
//    }

    public void userPause(int i) {
//        userPause(i != 0);
    }

//    public void userPause(boolean shouldBePaused) {
//        if (mDeviceStateReceiver != null)
//            mDeviceStateReceiver.userPause(shouldBePaused);
//    }

    public void stopVpn(int i) {
//        stopVpn(i != 0);
    }

//    public void stopVpn(boolean replaceConnection) {
//        if (getManagement() != null) {
//            getManagement().stopVPN(replaceConnection);
//        }
//    }

    @Override
    public void onCreate() {
        Log.e(TAG, "onCreate:");
        super.onCreate();
    }

    @Override
    public void onRevoke() {
        Log.e(TAG, "VPN permission revoked by OS (e.g. other VPN program started), stopping VPN");
        endVpnService();
    }

    @Override
    public void onDestroy() {
        Log.e(TAG, "onDestroy:");
    }

    public void startVpnConfig(String inlineConfig) {
        //todo this.mProfile = new ConfigParser().parseConfig(new StringReader(inlineConfig));
        this.startService(new Intent(this, OpenVPNService.class));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startOpenVPN(startId);
        return START_STICKY;
    }

    public void startOpenVPN(int startId) {
//        if (mProfile == null) {
//            stopSelf(startId);
//            return;
//        }
        OpenVpnManagementThread mManagement = new OpenVpnManagementThread(this);
        if (!mManagement.openManagementInterface()) {
            endVpnService();
            return;
        }
        mManagement.start();
        Log.i(TAG, "started Socket Thread");
        synchronized (mProcessLock) {
            mProcessThread = new OpenVPNThread(this);
            mProcessThread.start();
        }
    }


    public void openvpnStopped() {
        endVpnService();
    }


    public void endVpnService() {
        synchronized (mProcessLock) {
            mProcessThread = null;
        }
    }
}
