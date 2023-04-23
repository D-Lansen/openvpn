package world.daochen.minivpn;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends Activity {

    private IBinder mBinder;

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
        this.bindService();
    }



    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String abi = Native.getStringFromJNI() + ":" + Native.getNativeAbi();
        ((TextView) findViewById(R.id.sample_text)).setText(abi);

        findViewById(R.id.btn_1).setOnClickListener(view -> {
                Log.e("lichen", "onClick");
                startVpn("client.ovpn");
            }
        );
    }

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

}