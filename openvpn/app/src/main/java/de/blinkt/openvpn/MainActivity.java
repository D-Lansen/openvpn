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
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.RemoteException;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;

import de.blinkt.openvpn.core.ConfigParser;
import de.blinkt.openvpn.core.IOpenVPNServiceInternal;
import de.blinkt.openvpn.core.OpenVPNService;
import de.blinkt.openvpn.core.ProfileManager;

public class MainActivity extends Activity {

    private static final int MSG_UPDATE_STATE = 0;
    private static final int MSG_UPDATE_MYIP = 1;
    private static final int START_PROFILE = 2;

    protected IOpenVPNServiceInternal m_service = null;
    private Handler mHandler = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.control).setOnClickListener(v -> {
            if (((Button) findViewById(R.id.control)).getText().toString().equals("RESUME")) {
                try {
                    m_service.userPause(false);
                } catch (RemoteException e) {
                    e.printStackTrace();
                }
                ((Button) findViewById(R.id.control)).setText("PAUSE");
                return;
            }
            if (((Button) findViewById(R.id.control)).getText().toString().equals("PAUSE")) {
                try {
                    m_service.userPause(true);
                } catch (RemoteException e) {
                    e.printStackTrace();
                }
                ((Button) findViewById(R.id.control)).setText("RESUME");
                return;
            }
        });
        findViewById(R.id.disconnect).setOnClickListener(v -> {
            try {
                m_service.stopVPN(false);
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
            try {
                conf = this.getAssets().open("lichen03.ovpn");
            } catch (IOException e) {
                return;
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
            startVpn(config.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
        Toast.makeText(this, "Profile Add", Toast.LENGTH_LONG).show();
    }

    public void startVpn(String inlineConfig) {
        ConfigParser cp = new ConfigParser();
        try {
            cp.parseConfig(new StringReader(inlineConfig));
            VpnProfile vp = cp.convertProfile();
            vp.mName = "Remote APP VPN";
            if (vp.checkProfile(getApplicationContext()) != R.string.no_error_found)
                Log.e("MainActivity", "startVpn.err:" + getString(vp.checkProfile(getApplicationContext())));

            vp.mProfileCreator = "de.blinkt.openvpn";

            ProfileManager.setTemporaryProfile(MainActivity.this, vp);

            Context context = getBaseContext();
            Intent startVPN = vp.getStartServiceIntent(context);
            if (startVPN != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                    context.startForegroundService(startVPN);
                else
                    context.startService(startVPN);
            }

        } catch (IOException | ConfigParser.ConfigParseError e) {
            Log.e("MainActivity", "startVpn.err:" + e.getMessage());
        }
    }

    private void bindService() {
        Intent intent = new Intent(getBaseContext(), OpenVPNService.class);
        intent.setAction(OpenVPNService.START_SERVICE);
        this.bindService(intent, conn, Context.BIND_AUTO_CREATE);
    }

    private ServiceConnection conn = new ServiceConnection() {

        @Override
        public void onServiceConnected(ComponentName className, IBinder service) {
            m_service = IOpenVPNServiceInternal.Stub.asInterface(service);
        }

        @Override
        public void onServiceDisconnected(ComponentName arg0) {
            m_service = null;
        }
    };

    private void initHandler() {
        mHandler = new Handler(new Handler.Callback() {
            @Override
            public boolean handleMessage(Message msg) {
                if (msg.what == MSG_UPDATE_MYIP) {
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
        this.bindService();
    }

    @Override
    public void onStop() {
        super.onStop();
        this.unbindService(conn);
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == Activity.RESULT_OK) {
            if (requestCode == START_PROFILE) {
                startEmbeddedProfile();
            }
        }
    }

    private void prepareStartProfile(int requestCode) throws RemoteException {
        Intent requestpermission = VpnService.prepare(getBaseContext());
        if (requestpermission == null) {
            onActivityResult(requestCode, Activity.RESULT_OK, null);
        } else {
            startActivityForResult(requestpermission, requestCode);
        }
    }

    public String getMyOwnIP() throws IOException {
        StringBuilder resp = new StringBuilder();
//        https://ipv4.ddnspod.com
//        https://api-ipv4.ip.sb/ip
//        https://myip.ipip.net
//        https://ddns.oray.com/checkip
//        https://speed.neu.edu.cn/getIP.php
//        https://icanhazip.com
        URL url = new URL("https://myip.ipip.net/");
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
