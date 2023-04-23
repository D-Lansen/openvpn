package world.daochen.minivpn;

import android.content.Context;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.util.Log;

import java.io.IOException;

public class OpenVpnManagementThread extends Thread{

    private static final String TAG = "OpenVpnManagementThread";
    private final OpenVPNService mService;

    private LocalServerSocket mServerSocket;

    public OpenVpnManagementThread(OpenVPNService service) {
        this.mService = service;
    }

    @Override
    public void run() {

    }


    public boolean openManagementInterface() {
        // Could take a while to open connection
        int tries = 8;

        String socketName = (mService.getCacheDir().getAbsolutePath() + "/" + "mgmtsocket");

        LocalSocket ls = new LocalSocket();

        while (tries > 0 && !ls.isBound()) {
            try {
                ls.bind(new LocalSocketAddress(socketName,
                        LocalSocketAddress.Namespace.FILESYSTEM));
            } catch (IOException e) {
                // wait 300 ms before retrying
                try {
                    //noinspection BusyWait
                    Thread.sleep(300);
                } catch (InterruptedException ignored) {
                }
            }
            tries--;
        }

        try {
            mServerSocket = new LocalServerSocket(ls.getFileDescriptor());
            return true;
        } catch (IOException e) {
            Log.e(TAG,"",e);
        }
        return false;
    }

}
