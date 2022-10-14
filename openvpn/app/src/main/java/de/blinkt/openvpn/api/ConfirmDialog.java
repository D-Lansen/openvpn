/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.blinkt.openvpn.api;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import de.blinkt.openvpn.core.IOpenVPNServiceInternal;
import de.blinkt.openvpn.core.OpenVPNService;

public class ConfirmDialog extends Activity {

    private static final String TAG = "OpenVPNVpnConfirm";

    public static final String EXTRA_PACKAGE_NAME = "android.intent.extra.PACKAGE_NAME";

    public static final String ANONYMOUS_PACKAGE = "de.blinkt.openvpn.ANYPACKAGE";

    private ServiceConnection mConnection = new ServiceConnection() {

        private IOpenVPNServiceInternal mService;

        @Override
        public void onServiceConnected(ComponentName className, IBinder service) {
            mService = IOpenVPNServiceInternal.Stub.asInterface(service);
            try {
                String mPackage = "de.blinkt.openvpn";
                mService.addAllowedExternalApp(mPackage);
                setResult(RESULT_OK);
            } catch (RemoteException e) {
                Log.e(TAG, "onResume:", e);
            } finally {
                finish();
                unbindService(mConnection);
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName arg0) {
            mService = null;
        }

    };

    @Override
    protected void onResume() {
        super.onResume();
        Intent serviceintent = new Intent(this, OpenVPNService.class);
        serviceintent.setAction(OpenVPNService.START_SERVICE);
        bindService(serviceintent, mConnection, Context.BIND_AUTO_CREATE);
    }

}

