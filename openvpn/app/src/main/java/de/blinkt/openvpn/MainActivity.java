/*
 * Copyright (c) 2012-2022 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.RemoteException;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.UnknownHostException;

import de.blinkt.openvpn.api.IOpenVPNAPIService;
import de.blinkt.openvpn.api.IOpenVPNStatusCallback;

public class MainActivity extends Activity {

    private static final int MSG_UPDATE_STATE = 0;
    private static final int MSG_UPDATE_MYIP = 1;
    private static final int START_PROFILE = 2;
    private static final int START_PROFILE_BYUUID = 3;
    private static final int ICS_OPENVPN_PERMISSION = 7;
    private static final int PROFILE_ADD_NEW = 8;
    private static final int PROFILE_ADD_NEW_EDIT = 9;

    protected IOpenVPNAPIService mService = null;
    private Handler mHandler;
    private String mStartUUID = null;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.disconnect).setOnClickListener(v -> {
            try {
                mService.disconnect();
            } catch (RemoteException e) {
                e.printStackTrace();
            }
        });
        findViewById(R.id.getMyIP).setOnClickListener(v -> {
            new Thread() {
                @Override
                public void run() {
                    try {
                        String myip = getMyOwnIP();
                        Message msg = Message.obtain(mHandler, MSG_UPDATE_MYIP, myip);
                        msg.sendToTarget();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }.start();
        });
        findViewById(R.id.profile).setOnClickListener(v -> {
            try {
                prepareStartProfile(START_PROFILE);
            } catch (RemoteException e) {
                e.printStackTrace();
            }
        });
    }

    private void startEmbeddedProfile() {
        try {
            InputStream conf;
            /* Try opening test.local.conf first */
            try {
                conf = this.getAssets().open("lichen02.ovpn");
            } catch (IOException e) {
                conf = this.getAssets().open("lichen01.ovpn");
            }
            BufferedReader br = new BufferedReader(new InputStreamReader(conf));
            StringBuilder config = new StringBuilder();
            String line;
            while (true) {
                line = br.readLine();
                if (line == null)
                    break;
                config.append(line).append("\n");
            }
            br.close();
            conf.close();
            mService.startVPN(config.toString());
        } catch (IOException | RemoteException e) {
            e.printStackTrace();
        }
        Toast.makeText(this, "Profile Add", Toast.LENGTH_LONG).show();
    }

    private void bindService() {
        Intent openvpnService = new Intent(IOpenVPNAPIService.class.getName());
        openvpnService.setPackage("de.blinkt.openvpn");
        this.bindService(openvpnService, mConnection, Context.BIND_AUTO_CREATE);
    }

    private ServiceConnection mConnection = new ServiceConnection() {
        public void onServiceConnected(ComponentName className, IBinder service) {
            mService = IOpenVPNAPIService.Stub.asInterface(service);
            try {
                // Request permission to use the API
                Intent i = mService.prepare(this.getClass().getPackage().getName());
                if (i != null) {
                    startActivityForResult(i, ICS_OPENVPN_PERMISSION);
                } else {
                    onActivityResult(ICS_OPENVPN_PERMISSION, Activity.RESULT_OK, null);
                }
            } catch (RemoteException e) {
                e.printStackTrace();
            }
        }

        public void onServiceDisconnected(ComponentName className) {
            // This is called when the connection with the service has been
            // unexpectedly disconnected -- that is, its process crashed.
            mService = null;
        }
    };

    private void unbindService() {
        this.unbindService(mConnection);
    }

    private IOpenVPNStatusCallback mCallback = new IOpenVPNStatusCallback.Stub() {
        /**
         * This is called by the remote service regularly to tell us about
         * new values.  Note that IPC calls are dispatched through a thread
         * pool running in each process, so the code executing here will
         * NOT be running in our main thread like most other things -- so,
         * to update the UI, we need to use a Handler to hop over there.
         */

        @Override
        public void newStatus(String uuid, String state, String message, String level)
                throws RemoteException {
            Message msg = Message.obtain(mHandler, MSG_UPDATE_STATE, state + "|" + message);
            msg.sendToTarget();
        }

    };

    private void initHandler(){
        mHandler = new Handler(new Handler.Callback() {
            @Override
            public boolean handleMessage(@NonNull Message msg) {
                if (msg.what == MSG_UPDATE_STATE) {
                    ((TextView) findViewById(R.id.status)).setText((CharSequence) msg.obj);
                } else if (msg.what == MSG_UPDATE_MYIP) {
                    ((TextView) findViewById(R.id.MyIpText)).setText((CharSequence) msg.obj);
                }
                return true;
            }
        });
    }

    @Override
    public void onStart() {
        super.onStart();
        initHandler();
        bindService();
    }

    @Override
    public void onStop() {
        super.onStop();
        unbindService();
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == Activity.RESULT_OK) {
            if (requestCode == START_PROFILE_BYUUID)
                try {
                    mService.startProfile(mStartUUID);
                } catch (RemoteException e) {
                    e.printStackTrace();
                }
            if (requestCode == ICS_OPENVPN_PERMISSION) {
                try {
                    mService.registerStatusCallback(mCallback);
                } catch (RemoteException e) {
                    e.printStackTrace();
                }
            }
            if ((requestCode == PROFILE_ADD_NEW) ||
                    (requestCode == PROFILE_ADD_NEW_EDIT) ||
                    (requestCode == START_PROFILE)) {
                startEmbeddedProfile();
            }
        }
    }

    private void prepareStartProfile(int requestCode) throws RemoteException {
        Intent requestpermission = mService.prepareVPNService();
        if (requestpermission == null) {
            onActivityResult(requestCode, Activity.RESULT_OK, null);
        } else {
            startActivityForResult(requestpermission, requestCode);
        }
    }

    public String getMyOwnIP() throws UnknownHostException, IOException, RemoteException,
            IllegalArgumentException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {
        StringBuilder resp = new StringBuilder();

        URL url = new URL("https://icanhazip.com");
        HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            while (true) {
                String line = in.readLine();
                if (line == null)
                    return resp.toString();
                resp.append(line);
            }
        } finally {
            urlConnection.disconnect();
        }
    }

}
