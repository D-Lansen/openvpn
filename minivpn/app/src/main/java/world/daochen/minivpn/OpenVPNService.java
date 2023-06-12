package world.daochen.minivpn;

import static world.daochen.minivpn.NetworkSpace.IpAddress;

import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.ProxyInfo;
import android.net.VpnService;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.system.OsConstants;
import android.text.TextUtils;
import android.util.Log;


import androidx.annotation.RequiresApi;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Vector;
import java.util.concurrent.ExecutionException;

public class OpenVPNService extends VpnService {
    private static final String TAG = "OpenVPNService";
    private static final String VPNSERVICE_TUN = "vpnservice-tun";
    private static final String ORBOT_PACKAGE_NAME = "org.torproject.android";
    private final Object mProcessLock = new Object();
    private OpenVPNThread mProcessThread = null;
    private DeviceStateReceiver mDeviceStateReceiver;
    private OpenVpnManagementThread mManagement = null;
    private final Vector<String> mDnsList = new Vector<>();
    private final NetworkSpace mRoutes = new NetworkSpace();
    private final NetworkSpace mRoutesV6 = new NetworkSpace();
    private VpnProfile mProfile;
    private String mDomain = null;
    private CidrIp mLocalIP = null;
    private String mRemoteGW;
    private String mLastTunCfg;
    private int mMtu;
    private String mLocalIPv6 = null;
    private ProxyInfo mProxyInfo;
    private boolean mStarting = false;

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
        return mBinder;
    }

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

    private void startVpnConfig(String inlineConfig) {
        ConfigParser cp = new ConfigParser();
        try {
            cp.parseConfig(new StringReader(inlineConfig));
            VpnProfile vp = cp.convertProfile();
            if (vp.checkProfile() !=  null){
                Log.e(TAG, "startVpn.err:" + vp.checkProfile());
            }
            vp.mProfileCreator = "world.daochen.minivpn";
            this.mProfile = vp;
            this.startService(new Intent(this, OpenVPNService.class));

        } catch (IOException | ConfigParser.ConfigParseError e) {
            Log.e("OpenVPNService", "startVpn.err:" + e.getMessage());
        }
    }

    public void userPause(int i) {
        userPause(i != 0);
    }

    public void userPause(boolean shouldBePaused) {
        if (mDeviceStateReceiver != null)
            mDeviceStateReceiver.userPause(shouldBePaused);
    }

    public void stopVpn(int i) {
        stopVpn(i != 0);
    }

    public void stopVpn(boolean replaceConnection) {
        if (mManagement != null) {
            mManagement.stopVPN(replaceConnection);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
    }

    @Override
    public void onRevoke() {
        Log.e(TAG, "VPN permission revoked by OS (e.g. other VPN program started), stopping VPN");
        endVpnService();
    }

    @Override
    public void onDestroy() {
        synchronized (mProcessLock) {
            if (mProcessThread != null) {
                mManagement.stopVPN(true);
            }
        }

        if (mDeviceStateReceiver != null) {
            unregisterDeviceStateReceiver();
        }
    }

    public void openvpnStopped() {
        endVpnService();
    }

    private void endVpnService() {
        synchronized (mProcessLock) {
            mProcessThread = null;
        }
        unregisterDeviceStateReceiver();
        mProcessThread = null;
        if (!mStarting) {
            stopForeground(true);
            stopSelf();
        }
    }
    synchronized void registerDeviceStateReceiver() {
        // Registers BroadcastReceiver to track network connection changes.
        IntentFilter filter = new IntentFilter();
        filter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        filter.addAction(Intent.ACTION_SCREEN_OFF);
        filter.addAction(Intent.ACTION_SCREEN_ON);
        // Fetch initial network state
        DeviceStateReceiver deviceStateReceiver = new DeviceStateReceiver(mManagement);
        deviceStateReceiver.networkStateChange(this);
        registerReceiver(deviceStateReceiver, filter);
        mDeviceStateReceiver = deviceStateReceiver;
    }

    synchronized void unregisterDeviceStateReceiver() {
        if (mDeviceStateReceiver != null){
            try {
                this.unregisterReceiver(mDeviceStateReceiver);
            } catch (IllegalArgumentException iae) {
                // I don't know why  this happens:
                // java.lang.IllegalArgumentException: Receiver not registered: de.blinkt.openvpn.NetworkSateReceiver@41a61a10
                // Ignore for now ...
                iae.printStackTrace();
            }
        }
        mDeviceStateReceiver = null;
    }

    private void addLocalNetworksToRoutes() {
        for (String net : NetworkUtils.getLocalNetworks(this, false)) {
            String[] netparts = net.split("/");
            String ipAddr = netparts[0];
            int netMask = Integer.parseInt(netparts[1]);
            if (ipAddr.equals(mLocalIP.mIp))
                continue;

            if (mProfile.mAllowLocalLAN)
                mRoutes.addIP(new CidrIp(ipAddr, netMask), false);
        }

        // IPv6 is Lollipop+ only so we can skip the lower than KITKAT case
        if (mProfile.mAllowLocalLAN) {
            for (String net : NetworkUtils.getLocalNetworks(this, true)) {
                addRouteV6(net, false);
            }
        }
    }

    public ParcelFileDescriptor openTun() {

        Builder builder = new Builder();

        Log.i(TAG, "Opening tun interface");

        if (mProfile == null) {
            Log.e(TAG, "OpenVPN tries to open a VPN descriptor with mProfile==null, please report this bug with log!");
            return null;
        }

        boolean allowUnsetAF = !mProfile.mBlockUnusedAddressFamilies;
        if (allowUnsetAF) {
            builder.allowFamily(OsConstants.AF_INET);
            builder.allowFamily(OsConstants.AF_INET6);
        }

        if (mLocalIP == null && mLocalIPv6 == null) {
            Log.e(TAG, "Refusing to open tun device without IP information");
            return null;
        }

        if (mLocalIP != null) {
            // OpenVPN3 manages excluded local networks by callback
            addLocalNetworksToRoutes();
            try {
                builder.addAddress(mLocalIP.mIp, mLocalIP.len);
            } catch (IllegalArgumentException iae) {
                Log.e(TAG, "Could not add DNS Server "+mLocalIP+", rejected by the system: "+iae.getLocalizedMessage());
                return null;
            }
        }

        if (mLocalIPv6 != null) {
            String[] ipv6parts = mLocalIPv6.split("/");
            try {
                builder.addAddress(ipv6parts[0], Integer.parseInt(ipv6parts[1]));
            } catch (IllegalArgumentException iae) {
                Log.e(TAG, "Could not configure IP Address "+mLocalIPv6+", rejected by the system: "+iae.getLocalizedMessage());
                return null;
            }
        }

        for (String dns : mDnsList) {
            try {
                builder.addDnsServer(dns);
            } catch (IllegalArgumentException iae) {
                Log.e(TAG, "Could not add DNS Server "+dns+", rejected by the system: "+iae.getLocalizedMessage());
            }
        }

        builder.setMtu(mMtu);

        Collection<IpAddress> positiveIPv4Routes = mRoutes.getPositiveIPList();
        Collection<IpAddress> positiveIPv6Routes = mRoutesV6.getPositiveIPList();

        if ("samsung".equals(Build.BRAND) && mDnsList.size() >= 1) {
            // Check if the first DNS Server is in the VPN range
            try {
                IpAddress dnsServer = new IpAddress(new CidrIp(mDnsList.get(0), 32), true);
                boolean dnsIncluded = false;
                for (IpAddress net : positiveIPv4Routes) {
                    if (net.containsNet(dnsServer)) {
                        dnsIncluded = true;
                    }
                }
                if (!dnsIncluded) {
                    String samsungWarning = String.format("Warning Samsung Android 5.0+ devices ignore DNS servers outside the VPN range. To enable DNS resolution a route to your DNS Server (%s) has been added.", mDnsList.get(0));
                    Log.w(TAG, samsungWarning);
                    positiveIPv4Routes.add(dnsServer);
                }
            } catch (Exception e) {
                // If it looks like IPv6 ignore error
                if (!mDnsList.get(0).contains(":")){
                    Log.e(TAG, "Error parsing DNS Server IP: "+ mDnsList.get(0));
                }
            }
        }


        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            installRoutesExcluded(builder, mRoutes);
            installRoutesExcluded(builder, mRoutesV6);
        } else {
            installRoutesPostiveOnly(builder, positiveIPv4Routes, positiveIPv6Routes);
        }


        if (mDomain != null)
            builder.addSearchDomain(mDomain);

        String ipv4info;
        String ipv6info;
        if (allowUnsetAF) {
            ipv4info = "(not set, allowed)";
            ipv6info = "(not set, allowed)";
        } else {
            ipv4info = "(not set)";
            ipv6info = "(not set)";
        }

        int ipv4len;
        if (mLocalIP != null) {
            ipv4len = mLocalIP.len;
            ipv4info = mLocalIP.mIp;
        } else {
            ipv4len = -1;
        }

        if (mLocalIPv6 != null) {
            ipv6info = mLocalIPv6;
        }

        if ((!mRoutes.getNetworks(false).isEmpty() || !mRoutesV6.getNetworks(false).isEmpty()) && isLockdownEnabledCompat()) {
            Log.i(TAG, "VPN lockdown enabled (do not allow apps to bypass VPN) enabled. Route exclusion will not allow apps to bypass VPN (e.g. bypass VPN for local networks)");
        }

        Log.i(TAG, "IpV4:"+ipv4info+" len:"+ipv4len);
        Log.i(TAG, "IpV6:"+ipv6info);
        Log.i(TAG, "Mtu:"+mMtu);
        Log.i(TAG, "Domain:"+mDomain);
        if (mProxyInfo != null) {
            Log.i(TAG, "HTTP Proxy:"+mProxyInfo.getHost()+" "+mProxyInfo.getPort());
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            /* On Tiramisu we install the routes exactly like promised */
            Log.d(TAG, "VpnService routes installed...");
            //VpnStatus.logDebug(R.string.routes_debug, TextUtils.join(", ", positiveIPv4Routes), TextUtils.join(", ", positiveIPv6Routes));
        }
        setAllowedVpnPackages(builder);
        // VPN always uses the default network
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            builder.setUnderlyingNetworks(null);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Setting this false, will cause the VPN to inherit the underlying network metered
            // value
            builder.setMetered(false);
        }

        String session = mProfile.mName;
        if (mLocalIP != null && mLocalIPv6 != null)
            session = session+" - "+mLocalIPv6+", "+mLocalIP;
        else if (mLocalIP != null)
            session = session+" - "+mLocalIP;
        else
            session = session+" - "+mLocalIPv6;

        builder.setSession(session);

        // No DNS Server, log a warning
        if (mDnsList.size() == 0){
            Log.i(TAG, "No DNS servers being used. Name resolution may not work. Consider setting custom DNS Servers. Please also note that Android will keep using your proxy settings specified for your mobile/Wi-Fi connection when no DNS servers are set.");
        }

        setHttpProxy(builder);

        mLastTunCfg = getTunConfigString();

        // Reset information
        mDnsList.clear();
        mRoutes.clear();
        mRoutesV6.clear();
        mLocalIP = null;
        mLocalIPv6 = null;
        mDomain = null;
        mProxyInfo = null;

        builder.setConfigureIntent(getGraphPendingIntent());

        try {
            //Debug.stopMethodTracing();
            ParcelFileDescriptor tun = builder.establish();
            if (tun == null){
                throw new NullPointerException("Android establish() method returned null (Really broken network configuration?)");
            }
            return tun;
        } catch (Exception e) {
            Log.e(TAG, "Failed to open the tun interface");
            Log.e(TAG, "Error:"+ e.getLocalizedMessage());
            return null;
        }
    }

    private boolean isLockdownEnabledCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return isLockdownEnabled();
        } else {
            /* We cannot determine this, return false */
            return false;
        }
    }
    public PendingIntent getGraphPendingIntent() {
        // Let the configure Button show the Log
        Intent intent = new Intent();
        intent.setComponent(new ComponentName(this, getPackageName() + ".activities.MainActivity"));

        intent.putExtra("PAGE", "graph");
        intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        PendingIntent startLW = null;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            startLW = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE);
        }
        intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        return startLW;
    }

    private void setAllowedVpnPackages(Builder builder) {
        boolean profileUsesOrBot = false;

        for (Connection c : mProfile.mConnections) {
            if (c.mProxyType == Connection.ProxyType.ORBOT) {
                profileUsesOrBot = true;
                break;
            }
        }

        if (profileUsesOrBot){
            Log.d(TAG, "VPN Profile uses at least one server entry with Orbot. Setting up VPN so that OrBot is not redirected over VPN.");
        }

        boolean atLeastOneAllowedApp = false;

        if (mProfile.mAllowedAppsVpnAreDisallowed && profileUsesOrBot) {
            try {
                builder.addDisallowedApplication(ORBOT_PACKAGE_NAME);
            } catch (PackageManager.NameNotFoundException e) {
                Log.d(TAG, "Orbot not installed?");
            }
        }

        for (Object pkg : mProfile.mAllowedAppsVpn) {
            try {
                if (mProfile.mAllowedAppsVpnAreDisallowed) {
                    builder.addDisallowedApplication((String) pkg);
                } else {
                    if (!(profileUsesOrBot && pkg.equals(ORBOT_PACKAGE_NAME))) {
                        builder.addAllowedApplication((String) pkg);
                        atLeastOneAllowedApp = true;
                    }
                }
            } catch (PackageManager.NameNotFoundException e) {
                mProfile.mAllowedAppsVpn.remove(pkg);
                Log.i(TAG, "app_no_longer_exists"+(String) pkg);
            }
        }

        if (!mProfile.mAllowedAppsVpnAreDisallowed && !atLeastOneAllowedApp) {
            Log.d(TAG, "No allowed app added. Adding ourselves "+getPackageName()+" to have at least one app in the allowed app list to not allow all apps");
            try {
                builder.addAllowedApplication(getPackageName());
            } catch (PackageManager.NameNotFoundException e) {
                Log.e(TAG, "This should not happen: \" + e.getLocalizedMessage()");
            }
        }

        if (mProfile.mAllowedAppsVpnAreDisallowed) {
            Log.d(TAG, "Disallowed VPN apps:");
        } else {
            Log.d(TAG, "Allowed VPN apps:");
        }

        if (mProfile.mAllowAppVpnBypass) {
            builder.allowBypass();
            Log.d(TAG, "Apps may bypass VPN");
        }
    }

    private String getTunConfigString() {
        // The format of the string is not important, only that
        // two identical configurations produce the same result
        String cfg = "TUNCFG UNQIUE STRING ips:";

        if (mLocalIP != null)
            cfg += mLocalIP.toString();
        if (mLocalIPv6 != null)
            cfg += mLocalIPv6;

        cfg += "routes: " + TextUtils.join("|", mRoutes.getNetworks(true)) + TextUtils.join("|", mRoutesV6.getNetworks(true));
        cfg += "excl. routes:" + TextUtils.join("|", mRoutes.getNetworks(false)) + TextUtils.join("|", mRoutesV6.getNetworks(false));
        cfg += "dns: " + TextUtils.join("|", mDnsList);
        cfg += "domain: " + mDomain;
        cfg += "mtu: " + mMtu;
        cfg += "proxyInfo: " + mProxyInfo;
        return cfg;
    }

    @RequiresApi(api = 33)
    private void installRoutesExcluded(Builder builder, NetworkSpace routes) {
        for (IpAddress ipIncl : routes.getNetworks(true)) {
            try {
                builder.addRoute(ipIncl.getPrefix());
            } catch (UnknownHostException | IllegalArgumentException ia) {
                Log.e(TAG, "Route rejected by Android"+ ipIncl + " " + ia.getLocalizedMessage());
            }
        }
        for (IpAddress ipExcl : routes.getNetworks(false)) {
            try {
                builder.excludeRoute(ipExcl.getPrefix());
            } catch (UnknownHostException | IllegalArgumentException ia) {
                Log.e(TAG, "Route rejected by Android"+ ipExcl + " " + ia.getLocalizedMessage());
            }
        }
    }

    private void installRoutesPostiveOnly(Builder builder, Collection<IpAddress> positiveIPv4Routes, Collection<IpAddress> positiveIPv6Routes) {
        IpAddress multicastRange = new IpAddress(new CidrIp("224.0.0.0", 3), true);
        for (IpAddress route : positiveIPv4Routes) {
            try {
                if (multicastRange.containsNet(route)){
                    Log.d(TAG, "Ignoring multicast route:"+route);
                }
                else{
                    builder.addRoute(route.getIPv4Address(), route.networkMask);
                }
            } catch (IllegalArgumentException ia) {
                Log.e(TAG, "Route rejected by Android"+ route + " " + ia.getLocalizedMessage());
            }
        }

        for (IpAddress route6 : positiveIPv6Routes) {
            try {
                builder.addRoute(route6.getIPv6Address(), route6.networkMask);
            } catch (IllegalArgumentException ia) {
                Log.e(TAG, "Route rejected by Android"+ route6 + " " + ia.getLocalizedMessage());
            }
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startOpenVPN(startId);
        return START_STICKY;
    }

    public void startOpenVPN(int startId) {

        if (mProfile == null) {
            stopSelf(startId);
            return;
        }

        // Set a flag that we are starting a new VPN
        mStarting = true;
        // Stop the previous session by interrupting the thread.
        stopOldOpenVPNProcess();
        // An old running VPN should now be exited
        mStarting = false;

        mManagement = new OpenVpnManagementThread(this);
        if (!mManagement.openManagementInterface()) {
            endVpnService();
            return;
        }
        new Thread(mManagement).start();
        Log.i(TAG, "started Socket Thread");
        synchronized (mProcessLock) {
            mProcessThread = new OpenVPNThread(this);
            mProcessThread.start();
        }

        try {
            mProfile.writeConfigFileOutput(this, mProcessThread.getOpenVPNStdin());
        } catch (IOException | ExecutionException | InterruptedException e) {
            Log.e(TAG, "Error generating config file", e);
            endVpnService();
            return;
        }

        if (mDeviceStateReceiver != null) {
            unregisterDeviceStateReceiver();
        }
        registerDeviceStateReceiver();
    }

    private void stopOldOpenVPNProcess() {
        if (mManagement != null) {
            if (mManagement.stopVPN(true)) {
                // an old was asked to exit, wait 1s
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    //ignore
                }
            }
        }
        forceStopOpenVpnProcess();
    }

    public void forceStopOpenVpnProcess() {
        synchronized (mProcessLock) {
            if (mProcessThread != null) {
                mProcessThread.setReplaceConnection();
                mProcessThread.interrupt();
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    //ignore
                }
            }
        }
    }


    private void setHttpProxy(Builder builder) {
        if (mProxyInfo != null && Build.VERSION.SDK_INT >= 29) {
            builder.setHttpProxy(mProxyInfo);
        } else if (mProxyInfo != null) {
            Log.w(TAG,"HTTP Proxy needs Android 10 or later.");
        }
    }

    public void addDNS(String dns) {
        mDnsList.add(dns);
    }
    public void setDomain(String domain) {
        if (mDomain == null) {
            Log.i(TAG, "setDomain");
            mDomain = domain;
        }
    }

    public void addHttpProxy(String proxy, int port) {
        try {
            mProxyInfo = ProxyInfo.buildDirectProxy(proxy, port);
        } catch (Exception e) {
            Log.e(TAG,"Could not set proxy" + e.getLocalizedMessage());
        }
    }

    public void addRoute(CidrIp route, boolean include) {
        mRoutes.addIP(route, include);
    }

    public void addRoute(String dest, String mask, String gateway, String device) {
        CidrIp route = new CidrIp(dest, mask);
        boolean include = isAndroidTunDevice(device);

        IpAddress gatewayIP = new IpAddress(new CidrIp(gateway, 32), false);

        if (mLocalIP == null) {
            Log.e(TAG,"Local IP address unset and received. Neither pushed server config nor local config specifies an IP addresses. Opening tun device is most likely going to fail.");
            return;
        }
        IpAddress localNet = new IpAddress(mLocalIP, true);
        if (localNet.containsNet(gatewayIP))
            include = true;

        if (gateway != null &&
                (gateway.equals("255.255.255.255") || gateway.equals(mRemoteGW)))
            include = true;


        if (route.len == 32 && !mask.equals("255.255.255.255")) {
            Log.w(TAG,"Cannot make sense of "+dest+" and "+mask+" as IP route with CIDR netmask, using /32 as netmask.");
        }

        if (route.normalise()){
            Log.w(TAG,"Corrected route "+dest+"/"+route.len+" to "+route.mIp+"/"+route.len);
        }

        mRoutes.addIP(route, include);
    }

    private boolean isAndroidTunDevice(String device) {
        return device != null &&
                (device.startsWith("tun") || "(null)".equals(device) || VPNSERVICE_TUN.equals(device));
    }
    public void addRouteV6(String network, String device) {
        // Tun is opened after ROUTE6, no device name may be present
        boolean included = isAndroidTunDevice(device);
        addRouteV6(network, included);
    }

    public void addRouteV6(String network, boolean included) {
        String[] v6parts = network.split("/");
        try {
            Inet6Address ip = (Inet6Address) InetAddress.getAllByName(v6parts[0])[0];
            int mask = Integer.parseInt(v6parts[1]);
            mRoutesV6.addIPv6(ip, mask, included);
        } catch (UnknownHostException e) {
            Log.e(TAG, "",e);
        }
    }

    public void setMtu(int mtu) {
        mMtu = mtu;
    }

    public void setLocalIP(String local, String netmask, int mtu, String mode) {
        mLocalIP = new CidrIp(local, netmask);
        mMtu = mtu;
        mRemoteGW = null;

        long netMaskAsInt = CidrIp.getLong(netmask);

        if (mLocalIP.len == 32 && !netmask.equals("255.255.255.255")) {
            // get the netmask as IP

            int masklen;
            long mask;
            if ("net30".equals(mode)) {
                masklen = 30;
                mask = 0xfffffffc;
            } else {
                masklen = 31;
                mask = 0xfffffffe;
            }

            // Netmask is Ip address +/-1, assume net30/p2p with small net
            if ((netMaskAsInt & mask) == (mLocalIP.getLong() & mask)) {
                mLocalIP.len = masklen;
            } else {
                mLocalIP.len = 32;
                if (!"p2p".equals(mode)){
                    Log.w(TAG,"Got interface information "+local+" and "+netmask+", assuming second address is peer address of remote. Using /32 netmask for local IP. Mode given by OpenVPN is "+mode);
                }
            }
        }
        if (("p2p".equals(mode) && mLocalIP.len < 32) || ("net30".equals(mode) && mLocalIP.len < 30)) {
            Log.w(TAG,"Vpn topology "+local+" specified but ifconfig "+netmask+" "+ mode+" looks more like an IP address with a network mask. Assuming subnet topology.");
        }


        /* Workaround for Lollipop and higher, it does not route traffic to the VPNs own network mask */
        if (mLocalIP.len <= 31) {
            CidrIp interfaceRoute = new CidrIp(mLocalIP.mIp, mLocalIP.len);
            interfaceRoute.normalise();
            addRoute(interfaceRoute, true);
        }


        // Configurations are sometimes really broken...
        mRemoteGW = netmask;
    }

    public void setLocalIpV6(String ipV6) {
        mLocalIPv6 = ipV6;
    }

    public OpenVpnManagementThread getManagement() {
        return mManagement;
    }

    public String getTunReopenStatus() {
        String currentConfiguration = getTunConfigString();
        if (currentConfiguration.equals(mLastTunCfg)) {
            return "NOACTION";
        } else {
            return "OPEN_BEFORE_CLOSE";
        }
    }
}
