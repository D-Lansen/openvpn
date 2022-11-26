package de.blinkt.openvpn.core;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.RemoteException;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import de.blinkt.openvpn.R;

public class MainActivity extends Activity {

//    private static final int MSG_UPDATE_STATE = 0;
    private static final int MSG_UPDATE_MYIP = 1;
    private static final int START_PROFILE = 2;

    private Handler mHandler = null;
    private IBinder mBinder;

    private final ServiceConnection mServiceConn = new ServiceConnection() {
        @Override
        public void onServiceDisconnected(ComponentName name) {
            Log.i("client", "mServiceConnPlus onServiceDisconnected");
        }

        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            Log.i("client", " mServiceConnPlus onServiceConnected");
            mBinder = service;
        }
    };

    public void startVpn(String ovpnName) {
        if (mBinder == null) {
            Log.e("MainActivity", "mPlusBinder == null");
            return;
        }
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
            _data.writeInterfaceToken("startVpn");
            _data.writeString(ovpnName);
            mBinder.transact(0x001, _data, _reply, 0);
            _reply.readException();
        } catch (RemoteException e) {
            e.printStackTrace();
        } finally {
            _reply.recycle();
            _data.recycle();
        }
    }

    public void userPause(int i) {
        if (mBinder == null) {
            Log.e("MainActivity", "mPlusBinder == null");
            return;
        }
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
            _data.writeInterfaceToken("userPause");
            _data.writeInt(i);
            mBinder.transact(0x010, _data, _reply, 0);
            _reply.readException();
        } catch (RemoteException e) {
            e.printStackTrace();
        } finally {
            _reply.recycle();
            _data.recycle();
        }
    }

    public void stopVpn(int i) {
        if (mBinder == null) {
            Log.e("MainActivity", "mPlusBinder == null");
            return;
        }
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
            _data.writeInterfaceToken("stopVpn");
            _data.writeInt(i);
            mBinder.transact(0x011, _data, _reply, 0);
            _reply.readException();
        } catch (RemoteException e) {
            e.printStackTrace();
        } finally {
            _reply.recycle();
            _data.recycle();
        }
    }

    @SuppressLint("SetTextI18n")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.control).setOnClickListener(v -> {
            if (((Button) findViewById(R.id.control)).getText().toString().equals("RESUME")) {
                userPause(0);
                ((Button) findViewById(R.id.control)).setText("PAUSE");
                return;
            }
            if (((Button) findViewById(R.id.control)).getText().toString().equals("PAUSE")) {
                userPause(1);
                ((Button) findViewById(R.id.control)).setText("RESUME");
            }
        });
        findViewById(R.id.disconnect).setOnClickListener(v -> stopVpn(0));
        findViewById(R.id.getMyIP).setOnClickListener(v -> new Thread() {
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
        }.start());
        findViewById(R.id.profile).setOnClickListener(v -> {
            try {
                prepareStartProfile();
            } catch (RemoteException e) {
                e.printStackTrace();
            }
        });
    }

    private void bindService() {
        this.bindService(new Intent(this, OpenVPNService.class),
                mServiceConn, Context.BIND_AUTO_CREATE);
    }

    private void initHandler() {
        mHandler = new Handler(msg -> {
            if (msg.what == MSG_UPDATE_MYIP) {
                ((TextView) findViewById(R.id.MyIpText)).setText((CharSequence) msg.obj);
            }
            return true;
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
        this.unbindService(mServiceConn);
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == Activity.RESULT_OK) {
            if (requestCode == START_PROFILE) {
                startVpn("client.ovpn");
            }
        }
    }

    private void prepareStartProfile() throws RemoteException {
        Intent requestpermission = VpnService.prepare(getBaseContext());
        if (requestpermission == null) {
            onActivityResult(START_PROFILE, Activity.RESULT_OK, null);
        } else {
            startActivityForResult(requestpermission, START_PROFILE);
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
