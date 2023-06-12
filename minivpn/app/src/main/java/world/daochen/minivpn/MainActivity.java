package world.daochen.minivpn;

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
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class MainActivity extends Activity {
    private static final int START_PROFILE = 2;
    private IBinder mBinder;
    private Handler mHandler = null;

    private void bindService() {
        this.bindService(new Intent(this, OpenVPNService.class),
                new ServiceConnection() {
                    @Override
                    public void onServiceConnected(ComponentName componentName, IBinder iBinder) {
                        mBinder = iBinder;
                    }

                    @Override
                    public void onServiceDisconnected(ComponentName componentName) {

                    }
                }, Context.BIND_AUTO_CREATE);
    }

    @Override
    public void onStart() {
        super.onStart();
        initHandler();
        this.bindService();
    }

    private void initHandler() {
        mHandler = new Handler(msg -> {
            if (msg.what == 1) {
                ((TextView) findViewById(R.id.sample_text)).setText((CharSequence) msg.obj);
            }
            return true;
        });
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String abi = Native.getStringFromJNI() + ":" + Native.getNativeAbi();
        ((TextView) findViewById(R.id.sample_text)).setText(abi);

        findViewById(R.id.btn_1).setOnClickListener(view -> {
                    // startVpn("client.ovpn");
                    try {
                        prepareStartProfile();
                    } catch (RemoteException e) {
                        e.printStackTrace();
                    }
                }
        );

        findViewById(R.id.btn_2).setOnClickListener(view -> {
            ((TextView) findViewById(R.id.sample_text)).setText("abi");
                    new Thread(){
                        @Override
                        public void run() {
                            try {
                                Message.obtain(mHandler, 1, getMyOwnIP()).sendToTarget();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }.start();
                }
        );
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

    public void startVpn(String ovpnName) {
        if (mBinder == null) {
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

    private void prepareStartProfile() throws RemoteException {
        Intent requestPermission = VpnService.prepare(getBaseContext());
        if (requestPermission == null) {
            onActivityResult(START_PROFILE, Activity.RESULT_OK, null);
        } else {
            startActivityForResult(requestPermission, START_PROFILE);
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == Activity.RESULT_OK) {
            if (requestCode == START_PROFILE) {
                startVpn("client.ovpn");
            }
        }
    }

}