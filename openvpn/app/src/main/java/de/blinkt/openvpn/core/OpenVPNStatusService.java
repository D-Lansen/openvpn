/*
 * Copyright (c) 2012-2016 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.core;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.util.Pair;

import java.lang.ref.WeakReference;

/**
 * Created by arne on 08.11.16.
 */

public class OpenVPNStatusService extends Service implements VpnStatus.LogListener, VpnStatus.ByteCountListener, VpnStatus.StateListener {

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        VpnStatus.addLogListener(this);
        VpnStatus.addByteCountListener(this);
        VpnStatus.addStateListener(this);
        mHandler.setService(this);

    }

    @Override
    public void onDestroy() {
        super.onDestroy();

        VpnStatus.removeLogListener(this);
        VpnStatus.removeByteCountListener(this);
        VpnStatus.removeStateListener(this);

    }

    @Override
    public void newLog(LogItem logItem) {
        Message msg = mHandler.obtainMessage(SEND_NEW_LOGITEM, logItem);
        msg.sendToTarget();
    }

    @Override
    public void updateByteCount(long in, long out, long diffIn, long diffOut) {
        Message msg = mHandler.obtainMessage(SEND_NEW_BYTECOUNT, Pair.create(in, out));
        msg.sendToTarget();
    }

    static UpdateMessage mLastUpdateMessage;

    static class UpdateMessage {
        public String state;
        public String logmessage;
        public ConnectionStatus level;
        public Intent intent;
        int resId;

        UpdateMessage(String state, String logmessage, int resId, ConnectionStatus level, Intent intent) {
            this.state = state;
            this.resId = resId;
            this.logmessage = logmessage;
            this.level = level;
            this.intent = intent;
        }
    }


    @Override
    public void updateState(String state, String logmessage, int localizedResId, ConnectionStatus level, Intent intent) {

        mLastUpdateMessage = new UpdateMessage(state, logmessage, localizedResId, level, intent);
        Message msg = mHandler.obtainMessage(SEND_NEW_STATE, mLastUpdateMessage);
        msg.sendToTarget();
    }

    @Override
    public void setConnectedVPN(String uuid) {
        Message msg = mHandler.obtainMessage(SEND_NEW_CONNECTED_VPN, uuid);
        msg.sendToTarget();
    }

    private static final OpenVPNStatusHandler mHandler = new OpenVPNStatusHandler();

    private static final int SEND_NEW_LOGITEM = 100;
    private static final int SEND_NEW_STATE = 101;
    private static final int SEND_NEW_BYTECOUNT = 102;
    private static final int SEND_NEW_CONNECTED_VPN = 103;

    private static class OpenVPNStatusHandler extends Handler {
        WeakReference<OpenVPNStatusService> service = null;

        private void setService(OpenVPNStatusService statusService) {
            service = new WeakReference<>(statusService);
        }
    }
}