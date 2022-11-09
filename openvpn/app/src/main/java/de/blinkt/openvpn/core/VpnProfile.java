package de.blinkt.openvpn.core;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import android.text.TextUtils;

import androidx.annotation.NonNull;

import de.blinkt.openvpn.R;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Locale;
import java.util.UUID;
import java.util.Vector;

public class VpnProfile implements Serializable, Cloneable {
//    public static final String EXTRA_PROFILEUUID = "de.blinkt.openvpn.profileUUID";
    public static final String INLINE_TAG = "[[INLINE]]";
    public static final String DISPLAYNAME_TAG = "[[NAME]]";
    public static final int MAXLOGLEVEL = 4;
    public static final int CURRENT_PROFILE_VERSION = 10;
//    public static final int DEFAULT_MSSFIX_SIZE = 1280;
    public static final int TYPE_CERTIFICATES = 0;
    public static final int TYPE_PKCS12 = 1;
    public static final int TYPE_KEYSTORE = 2;
    public static final int TYPE_USERPASS = 3;
    public static final int TYPE_STATICKEYS = 4;
    public static final int TYPE_USERPASS_CERTIFICATES = 5;
    public static final int TYPE_USERPASS_PKCS12 = 6;
    public static final int TYPE_USERPASS_KEYSTORE = 7;
    public static final int TYPE_EXTERNAL_APP = 8;
    public static final int X509_VERIFY_TLSREMOTE = 0;
    public static final int X509_VERIFY_TLSREMOTE_COMPAT_NOREMAPPING = 1;
    public static final int X509_VERIFY_TLSREMOTE_DN = 2;
    public static final int X509_VERIFY_TLSREMOTE_RDN = 3;
    public static final int X509_VERIFY_TLSREMOTE_RDN_PREFIX = 4;
    public static final int AUTH_RETRY_NONE_FORGET = 0;
    public static final int AUTH_RETRY_NOINTERACT = 2;
    public static String DEFAULT_DNS1 = "9.9.9.9";
    public static String DEFAULT_DNS2 = "2620:fe::fe";
    public transient boolean profileDeleted = false;
    public int mAuthenticationType = TYPE_KEYSTORE;
    public String mName;
    public String mAlias;
    public String mClientCertFilename;
    public String mTLSAuthDirection = "";
    public String mTLSAuthFilename;
    public String mClientKeyFilename;
    public String mCaFilename;
    public boolean mUseLzo = false;
    public String mPKCS12Filename;
    public String mPKCS12Password;
    public boolean mUseTLSAuth = false;
    public String mDNS1 = DEFAULT_DNS1;
    public String mDNS2 = DEFAULT_DNS2;
    public String mIPv4Address;
    public String mIPv6Address;
    public boolean mOverrideDNS = false;
    public String mSearchDomain = "blinkt.de";
    public boolean mUseDefaultRoute = true;
    public boolean mUsePull = true;
    public String mCustomRoutes;
    public boolean mCheckRemoteCN = true;
    public boolean mExpectTLSCert = false;
    public String mRemoteCN = "";
    public String mPassword = "";
    public String mUsername = "";
    public boolean mRoutenopull = false;
    public boolean mUseRandomHostname = false;
    public boolean mUseFloat = false;
    public boolean mUseCustomConfig = false;
    public String mCustomConfigOptions = "";
    public String mVerb = "1";  //ignored
    public String mCipher = "";
    public boolean mNobind = true;
    public boolean mUseDefaultRoutev6 = true;
    public String mCustomRoutesv6 = "";
    public String mKeyPassword = "";
    public boolean mPersistTun = false;
    public String mConnectRetryMax = "-1";
    public String mConnectRetry = "2";
    public String mConnectRetryMaxTime = "300";
    public boolean mUserEditable = true;
    public String mAuth = "";
    public int mX509AuthType = X509_VERIFY_TLSREMOTE_RDN;
    public String mx509UsernameField = null;
    public boolean mAllowLocalLAN;
    public String mExcludedRoutes;
    public int mMssFix = 0; // -1 is default,
    public Connection[] mConnections;
    public boolean mRemoteRandom = false;
    public HashSet mAllowedAppsVpn = new HashSet<>();
    public boolean mAllowedAppsVpnAreDisallowed = true;
    public boolean mAllowAppVpnBypass = false;
    public String mCrlFilename;
    public String mProfileCreator;
    public String mExternalAuthenticator;
    public int mAuthRetry = AUTH_RETRY_NONE_FORGET;
    public int mTunMtu;
    public boolean mPushPeerInfo = false;
    public int mVersion = 0;
    // timestamp when the profile was last used
    public long mLastUsed;
    public String importedProfileHash;
    /* Options no longer used in new profiles */
    public String mServerName = "openvpn.example.com";
    public String mServerPort = "1194";
    public boolean mUseUdp = true;
    public boolean mTemporaryProfile = false;
    public String mDataCiphers = "";
    public boolean mBlockUnusedAddressFamilies = true;
    public boolean mCheckPeerFingerprint = false;
    public String mPeerFingerPrints = "";
    public int mCompatMode = 0;
    public boolean mUseLegacyProvider = false;
    public String mTlSCertProfile = "";

    private UUID mUuid;

    public VpnProfile(String name) {
        mUuid = UUID.randomUUID();
        mName = name;

        mConnections = new Connection[1];
        mConnections[0] = new Connection();
        mLastUsed = System.currentTimeMillis();
    }

    public static String openVpnEscape(String unescaped) {
        if (unescaped == null)
            return null;
        String escapedString = unescaped.replace("\\", "\\\\");
        escapedString = escapedString.replace("\"", "\\\"");
        escapedString = escapedString.replace("\n", "\\n");

        if (escapedString.equals(unescaped) && !escapedString.contains(" ") &&
                !escapedString.contains("#") && !escapedString.contains(";")
                && !escapedString.equals("") && !escapedString.contains("'"))
            return unescaped;
        else
            return '"' + escapedString + '"';
    }

    //! Put inline data inline and other data as normal escaped filename
    public static String insertFileData(String cfgentry, String fileData) {
        if (fileData == null) {
            return String.format("%s %s\n", cfgentry, "file missing in config profile");
        } else if (isEmbedded(fileData)) {
            String dataWithOutHeader = getEmbeddedContent(fileData);
            return String.format(Locale.ENGLISH, "<%s>\n%s\n</%s>\n", cfgentry, dataWithOutHeader, cfgentry);
        } else {
            return String.format(Locale.ENGLISH, "%s %s\n", cfgentry, openVpnEscape(fileData));
        }
    }

    public static String getDisplayName(String embeddedFile) {
        int start = DISPLAYNAME_TAG.length();
        int end = embeddedFile.indexOf(INLINE_TAG);
        return embeddedFile.substring(start, end);
    }

    public static String getEmbeddedContent(String data) {
        if (!data.contains(INLINE_TAG))
            return data;

        int start = data.indexOf(INLINE_TAG) + INLINE_TAG.length();
        return data.substring(start);
    }

    public static boolean isEmbedded(String data) {
        if (data == null)
            return false;
        return data.startsWith(INLINE_TAG) || data.startsWith(DISPLAYNAME_TAG);
    }

    static public String getEnvString(Context c) {
        return c.getPackageName();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof VpnProfile) {
            VpnProfile vpnProfile = (VpnProfile) obj;
            return mUuid.equals(vpnProfile.mUuid);
        } else {
            return false;
        }
    }

    public void clearDefaults() {
        mServerName = "unknown";
        mUsePull = false;
        mUseLzo = false;
        mUseDefaultRoute = false;
        mUseDefaultRoutev6 = false;
        mExpectTLSCert = false;
        mCheckRemoteCN = false;
        mPersistTun = false;
        mAllowLocalLAN = true;
        mPushPeerInfo = false;
        mMssFix = 0;
        mNobind = false;
    }

    public String getName() {
        if (TextUtils.isEmpty(mName))
            return "No profile name";
        return mName;
    }

    public String getConfigFile(Context context) {

        File cacheDir = context.getCacheDir();
        StringBuilder cfg = new StringBuilder();

        // Enable management interface
        cfg.append("# Config for OpenVPN 2.x\n");
        cfg.append("# Enables connection to GUI\n");
        cfg.append("management ");

        cfg.append(cacheDir.getAbsolutePath()).append("/").append("mgmtsocket");
        cfg.append(" unix\n");
        cfg.append("management-client\n");
        // Not needed, see updated man page in 2.3
        //cfg += "management-signal\n";
        cfg.append("management-query-passwords\n");
        cfg.append("management-hold\n\n");

        cfg.append(String.format("setenv IV_GUI_VER %s \n", openVpnEscape(getEnvString(context))));
        cfg.append("setenv IV_SSO openurl,webauth,crtext\n");
        String versionString = getPlatformVersionEnvString();
        cfg.append(String.format("setenv IV_PLAT_VER %s\n", openVpnEscape(versionString)));
        String hwaddr = NetworkUtils.getFakeMacAddrFromSAAID(context);
        if (hwaddr != null)
            cfg.append(String.format("setenv IV_HWADDR %s\n", hwaddr));

        if (mUseLegacyProvider)
            cfg.append("providers legacy default\n");

        if (!TextUtils.isEmpty(mTlSCertProfile) && mAuthenticationType != TYPE_STATICKEYS)
            cfg.append(String.format("tls-cert-profile %s\n", mTlSCertProfile));


        cfg.append("machine-readable-output\n");

        cfg.append("allow-recursive-routing\n");

        // Users are confused by warnings that are misleading...
        cfg.append("ifconfig-nowarn\n");

        boolean useTLSClient = (mAuthenticationType != TYPE_STATICKEYS);

        if (useTLSClient && mUsePull)
            cfg.append("client\n");
        else if (mUsePull)
            cfg.append("pull\n");
        else if (useTLSClient)
            cfg.append("tls-client\n");


        //cfg += "verb " + mVerb + "\n";
        cfg.append("verb " + MAXLOGLEVEL + "\n");

        if (mConnectRetryMax == null) {
            mConnectRetryMax = "-1";
        }

        if (!mConnectRetryMax.equals("-1"))
            cfg.append("connect-retry-max ").append(mConnectRetryMax).append("\n");

        if (TextUtils.isEmpty(mConnectRetry))
            mConnectRetry = "2";

        if (TextUtils.isEmpty(mConnectRetryMaxTime))
            mConnectRetryMaxTime = "300";


        cfg.append("connect-retry ").append(mConnectRetry).append(" ").append(mConnectRetryMaxTime).append("\n");

        cfg.append("resolv-retry 60\n");

        // We cannot use anything else than tun
        cfg.append("dev tun\n");

        boolean canUsePlainRemotes = true;

        if (mConnections.length == 1) {
            cfg.append(mConnections[0].getConnectionBlock());
        } else {
            for (Connection conn : mConnections) {
                canUsePlainRemotes = canUsePlainRemotes && conn.isOnlyRemote();
            }

            if (mRemoteRandom)
                cfg.append("remote-random\n");

            if (canUsePlainRemotes) {
                for (Connection conn : mConnections) {
                    if (conn.mEnabled) {
                        cfg.append(conn.getConnectionBlock());
                    }
                }
            }
        }


        switch (mAuthenticationType) {
            case VpnProfile.TYPE_USERPASS_CERTIFICATES:
                cfg.append("auth-user-pass\n");
            case VpnProfile.TYPE_CERTIFICATES:
                // Ca
                if (!TextUtils.isEmpty(mCaFilename)) {
                    cfg.append(insertFileData("ca", mCaFilename));
                }

                // Client Cert + Key
                cfg.append(insertFileData("key", mClientKeyFilename));
                cfg.append(insertFileData("cert", mClientCertFilename));

                break;
            case VpnProfile.TYPE_USERPASS_PKCS12:
                cfg.append("auth-user-pass\n");
            case VpnProfile.TYPE_PKCS12:
                cfg.append(insertFileData("pkcs12", mPKCS12Filename));

                if (!TextUtils.isEmpty(mCaFilename)) {
                    cfg.append(insertFileData("ca", mCaFilename));
                }
                break;

            case VpnProfile.TYPE_USERPASS_KEYSTORE:
                cfg.append("auth-user-pass\n");
            case VpnProfile.TYPE_KEYSTORE:
            case VpnProfile.TYPE_EXTERNAL_APP:
                break;
            case VpnProfile.TYPE_USERPASS:
                cfg.append("auth-user-pass\n");
                if (!TextUtils.isEmpty(mCaFilename))
                    cfg.append(insertFileData("ca", mCaFilename));
        }

        if (mCheckPeerFingerprint) {
            cfg.append("<peer-fingerprint>\n").append(mPeerFingerPrints).append("\n</peer-fingerprint>\n");
        }

        if (isUserPWAuth()) {
            if (mAuthRetry == AUTH_RETRY_NOINTERACT)
                cfg.append("auth-retry nointeract\n");
        }

        if (!TextUtils.isEmpty(mCrlFilename))
            cfg.append(insertFileData("crl-verify", mCrlFilename));

        if (mUseLzo) {
            cfg.append("comp-lzo\n");
        }

        if (mUseTLSAuth) {
            boolean useTlsCrypt = mTLSAuthDirection.equals("tls-crypt");
            boolean useTlsCrypt2 = mTLSAuthDirection.equals("tls-crypt-v2");

            if (mAuthenticationType == TYPE_STATICKEYS)
                cfg.append(insertFileData("secret", mTLSAuthFilename));
            else if (useTlsCrypt)
                cfg.append(insertFileData("tls-crypt", mTLSAuthFilename));
            else if (useTlsCrypt2)
                cfg.append(insertFileData("tls-crypt-v2", mTLSAuthFilename));
            else
                cfg.append(insertFileData("tls-auth", mTLSAuthFilename));

            if (!TextUtils.isEmpty(mTLSAuthDirection) && !useTlsCrypt && !useTlsCrypt2) {
                cfg.append("key-direction ");
                cfg.append(mTLSAuthDirection);
                cfg.append("\n");
            }

        }

        if (!mUsePull) {
            if (!TextUtils.isEmpty(mIPv4Address))
                cfg.append("ifconfig ").append(cidrToIPAndNetmask(mIPv4Address)).append("\n");

            if (!TextUtils.isEmpty(mIPv6Address)) {
                // Use our own ip as gateway since we ignore it anyway
                String fakegw = mIPv6Address.split("/", 2)[0];
                cfg.append("ifconfig-ipv6 ").append(mIPv6Address).append(" ").append(fakegw).append("\n");
            }

        }

        if (mUsePull && mRoutenopull)
            cfg.append("route-nopull\n");

        StringBuilder routes = new StringBuilder();

        if (mUseDefaultRoute)
            routes.append("route 0.0.0.0 0.0.0.0 vpn_gateway\n");
        else {
            for (String route : getCustomRoutes(mCustomRoutes)) {
                routes.append("route ").append(route).append(" vpn_gateway\n");
            }

            for (String route : getCustomRoutes(mExcludedRoutes)) {
                routes.append("route ").append(route).append(" net_gateway\n");
            }
        }


        if (mUseDefaultRoutev6)
            cfg.append("route-ipv6 ::/0\n");
        else
            for (String route : getCustomRoutesv6(mCustomRoutesv6)) {
                routes.append("route-ipv6 ").append(route).append("\n");
            }

        cfg.append(routes);

        if (mOverrideDNS || !mUsePull) {
            if (!TextUtils.isEmpty(mDNS1)) {
                cfg.append("dhcp-option DNS ").append(mDNS1).append("\n");
            }
            if (!TextUtils.isEmpty(mDNS2)) {
                cfg.append("dhcp-option DNS ").append(mDNS2).append("\n");
            }
            if (!TextUtils.isEmpty(mSearchDomain))
                cfg.append("dhcp-option DOMAIN ").append(mSearchDomain).append("\n");

        }

        if (mMssFix != 0) {
            if (mMssFix != 1450) {
                cfg.append(String.format(Locale.US, "mssfix %d\n", mMssFix));
            } else
                cfg.append("mssfix\n");
        }

        if (mTunMtu >= 48 && mTunMtu != 1500) {
            cfg.append(String.format(Locale.US, "tun-mtu %d\n", mTunMtu));
        }

        if (mNobind)
            cfg.append("nobind\n");


        // Authentication
        if (mAuthenticationType != TYPE_STATICKEYS) {
            if (mCheckRemoteCN) {
                if (mRemoteCN == null || mRemoteCN.equals(""))
                    cfg.append("verify-x509-name ").append(openVpnEscape(mConnections[0].mServerName)).append(" name\n");
                else
                    switch (mX509AuthType) {

                        // 2.2 style x509 checks
                        case X509_VERIFY_TLSREMOTE_COMPAT_NOREMAPPING:
                            cfg.append("compat-names no-remapping\n");
                        case X509_VERIFY_TLSREMOTE:
                            cfg.append("tls-remote ").append(openVpnEscape(mRemoteCN)).append("\n");
                            break;

                        case X509_VERIFY_TLSREMOTE_RDN:
                            cfg.append("verify-x509-name ").append(openVpnEscape(mRemoteCN)).append(" name\n");
                            break;

                        case X509_VERIFY_TLSREMOTE_RDN_PREFIX:
                            cfg.append("verify-x509-name ").append(openVpnEscape(mRemoteCN)).append(" name-prefix\n");
                            break;

                        case X509_VERIFY_TLSREMOTE_DN:
                            cfg.append("verify-x509-name ").append(openVpnEscape(mRemoteCN)).append("\n");
                            break;
                    }
                if (!TextUtils.isEmpty(mx509UsernameField))
                    cfg.append("x509-username-field ").append(openVpnEscape(mx509UsernameField)).append("\n");
            }
            if (mExpectTLSCert)
                cfg.append("remote-cert-tls server\n");
        }

        if (!TextUtils.isEmpty(mDataCiphers)) {
            cfg.append("data-ciphers ").append(mDataCiphers).append("\n");
        }

        if (mCompatMode > 0) {
            int major = mCompatMode / 10000;
            int minor = mCompatMode % 10000 / 100;
            int patch = mCompatMode % 100;
            cfg.append(String.format(Locale.US, "compat-mode %d.%d.%d\n", major, minor, patch));

        }

        if (!TextUtils.isEmpty(mCipher)) {
            cfg.append("cipher ").append(mCipher).append("\n");
        }

        if (!TextUtils.isEmpty(mAuth)) {
            cfg.append("auth ").append(mAuth).append("\n");
        }

        // Obscure Settings dialog
        if (mUseRandomHostname)
            cfg.append("#my favorite options :)\nremote-random-hostname\n");

        if (mUseFloat)
            cfg.append("float\n");

        if (mPersistTun) {
            cfg.append("persist-tun\n");
            cfg.append("# persist-tun also enables pre resolving to avoid DNS resolve problem\n");
            cfg.append("preresolve\n");
        }

        if (mPushPeerInfo)
            cfg.append("push-peer-info\n");

        if (!usesExtraProxyOptions()) {
            cfg.append("# Use system proxy setting\n");
            cfg.append("management-query-proxy\n");
        }

        if (mUseCustomConfig) {
            cfg.append("# Custom configuration options\n");
            cfg.append("# You are on your on own here :)\n");
            cfg.append(mCustomConfigOptions);
            cfg.append("\n");

        }

        if (!canUsePlainRemotes) {
            cfg.append("# Connection Options are at the end to allow global options (and global custom options) to influence connection blocks\n");
            for (Connection conn : mConnections) {
                if (conn.mEnabled) {
                    cfg.append("<connection>\n");
                    cfg.append(conn.getConnectionBlock());
                    cfg.append("</connection>\n");
                }
            }
        }
        return cfg.toString();
    }

    public String getPlatformVersionEnvString() {
        return String.format(Locale.US, "%d %s %s %s %s %s", Build.VERSION.SDK_INT, Build.VERSION.RELEASE,
                NativeUtils.getNativeAPI(), Build.BRAND, Build.BOARD, Build.MODEL);
    }

    private Collection<String> getCustomRoutes(String routes) {
        Vector<String> cidrRoutes = new Vector<>();
        if (routes == null) {
            // No routes set, return empty vector
            return cidrRoutes;
        }
        for (String route : routes.split("[\n \t]")) {
            if (!route.equals("")) {
                String cidrroute = cidrToIPAndNetmask(route);
                if (cidrroute == null)
                    return cidrRoutes;

                cidrRoutes.add(cidrroute);
            }
        }

        return cidrRoutes;
    }

    private Collection<String> getCustomRoutesv6(String routes) {
        Vector<String> cidrRoutes = new Vector<>();
        if (routes == null) {
            // No routes set, return empty vector
            return cidrRoutes;
        }
        for (String route : routes.split("[\n \t]")) {
            if (!route.equals("")) {
                cidrRoutes.add(route);
            }
        }
        return cidrRoutes;
    }

    private String cidrToIPAndNetmask(String route) {
        String[] parts = route.split("/");

        // No /xx, assume /32 as netmask
        if (parts.length == 1)
            parts = (route + "/32").split("/");

        if (parts.length != 2)
            return null;
        int len;
        try {
            len = Integer.parseInt(parts[1]);
        } catch (NumberFormatException ne) {
            return null;
        }
        if (len < 0 || len > 32)
            return null;


        long nm = 0xffffffffL;
        nm = (nm << (32 - len)) & 0xffffffffL;

        String netmask = String.format(Locale.ENGLISH, "%d.%d.%d.%d", (nm & 0xff000000) >> 24, (nm & 0xff0000) >> 16, (nm & 0xff00) >> 8, nm & 0xff);
        return parts[0] + "  " + netmask;
    }

    public void writeConfigFileOutput(Context context, OutputStream out) throws IOException {
        OutputStreamWriter cfg = new OutputStreamWriter(out);
        cfg.write(getConfigFile(context));
        cfg.flush();
        cfg.close();
    }

    public Intent getStartServiceIntent(Context context) {
        String prefix = context.getPackageName();
        Intent intent = new Intent(context, OpenVPNService.class);
        intent.putExtra(prefix + ".profileUUID", mUuid.toString());
        intent.putExtra(prefix + ".profileVersion", mVersion);
        return intent;
    }

    @NonNull
    @Override
    protected VpnProfile clone() throws CloneNotSupportedException {
        VpnProfile copy = (VpnProfile) super.clone();
        copy.mUuid = UUID.randomUUID();
        copy.mConnections = new Connection[mConnections.length];
        int i = 0;
        for (Connection conn : mConnections) {
            copy.mConnections[i++] = conn.clone();
        }
        copy.mAllowedAppsVpn = (HashSet)mAllowedAppsVpn.clone();
        return copy;
    }

    public VpnProfile copy(String name) {
        try {
            VpnProfile copy = clone();
            copy.mName = name;
            return copy;

        } catch (CloneNotSupportedException e) {
            e.printStackTrace();
            return null;
        }
    }

    //! Return an error if something is wrong
    public int checkProfile() {
        if (mAuthenticationType == TYPE_KEYSTORE || mAuthenticationType == TYPE_USERPASS_KEYSTORE || mAuthenticationType == TYPE_EXTERNAL_APP) {
            if (mAlias == null)
                return R.string.no_keystore_cert_selected;
        } else if (mAuthenticationType == TYPE_CERTIFICATES || mAuthenticationType == TYPE_USERPASS_CERTIFICATES) {
            if (TextUtils.isEmpty(mCaFilename) && !mCheckPeerFingerprint)
                return R.string.no_ca_cert_selected;
        }

        if (mCheckRemoteCN && mX509AuthType == X509_VERIFY_TLSREMOTE)
            return R.string.deprecated_tls_remote;

        if (!mUsePull || mAuthenticationType == TYPE_STATICKEYS) {
            if (mIPv4Address == null || cidrToIPAndNetmask(mIPv4Address) == null)
                return R.string.ipv4_format_error;
        }

        if (!mUseDefaultRoute) {
            if (!TextUtils.isEmpty(mCustomRoutes) && getCustomRoutes(mCustomRoutes).size() == 0)
                return R.string.custom_route_format_error;

            if (!TextUtils.isEmpty(mExcludedRoutes) && getCustomRoutes(mExcludedRoutes).size() == 0)
                return R.string.custom_route_format_error;
        }

        if (mUseTLSAuth && TextUtils.isEmpty(mTLSAuthFilename))
            return R.string.missing_tlsauth;

        if ((mAuthenticationType == TYPE_USERPASS_CERTIFICATES || mAuthenticationType == TYPE_CERTIFICATES)
                && (TextUtils.isEmpty(mClientCertFilename) || TextUtils.isEmpty(mClientKeyFilename)))
            return R.string.missing_certificates;

        boolean noRemoteEnabled = true;
        for (Connection c : mConnections) {
            if (c.mEnabled) {
                noRemoteEnabled = false;
                break;
            }
        }
        if (noRemoteEnabled)
            return R.string.remote_no_server_selected;

        for (Connection c : mConnections) {
            if (c.mProxyType == Connection.ProxyType.ORBOT) {
                if (usesExtraProxyOptions())
                    return R.string.error_orbot_and_proxy_options;
            }
        }

        String dataciphers = "";
        if (!TextUtils.isEmpty(dataciphers))
            dataciphers = mDataCiphers.toUpperCase(Locale.ROOT);

        String cipher = "BF-CBC";
        if (!TextUtils.isEmpty(mCipher))
            cipher = mCipher.toUpperCase(Locale.ROOT);

        if (!mUseLegacyProvider &&
                (dataciphers.contains("BF-CBC")
                        || (mCompatMode > 0 && mCompatMode < 20500)
                        && cipher.equals("BF-CBC"))) {
            return R.string.bf_cbc_requires_legacy;
        }

        // Everything okay
        return R.string.no_error_found;
    }

    public boolean isUserPWAuth() {
        switch (mAuthenticationType) {
            case TYPE_USERPASS:
            case TYPE_USERPASS_CERTIFICATES:
            case TYPE_USERPASS_KEYSTORE:
            case TYPE_USERPASS_PKCS12:
                return true;
            default:
                return false;
        }
    }

    public boolean requireTLSKeyPassword() {
        if (TextUtils.isEmpty(mClientKeyFilename))
            return false;
        StringBuilder data = new StringBuilder();
        if (isEmbedded(mClientKeyFilename))
            data = new StringBuilder(mClientKeyFilename);
        else {
            char[] buf = new char[2048];
            FileReader fr;
            try {
                fr = new FileReader(mClientKeyFilename);
                int len = fr.read(buf);
                while (len > 0) {
                    data.append(new String(buf, 0, len));
                    len = fr.read(buf);
                }
                fr.close();
            } catch (IOException e) {
                return false;
            }
        }

        if (data.toString().contains("Proc-Type: 4,ENCRYPTED"))
            return true;
        else return data.toString().contains("-----BEGIN ENCRYPTED PRIVATE KEY-----");
    }

    public int needUserPWInput(String transientCertOrPkcs12PW, String mTransientAuthPW) {
        if ((mAuthenticationType == TYPE_PKCS12 || mAuthenticationType == TYPE_USERPASS_PKCS12) &&
                (mPKCS12Password == null || mPKCS12Password.equals(""))) {
            if (transientCertOrPkcs12PW == null)
                return R.string.pkcs12_file_encryption_key;
        }

        if (mAuthenticationType == TYPE_CERTIFICATES || mAuthenticationType == TYPE_USERPASS_CERTIFICATES) {
            if (requireTLSKeyPassword() && TextUtils.isEmpty(mKeyPassword))
                if (transientCertOrPkcs12PW == null) {
                    return R.string.private_key_password;
                }
        }

        if (isUserPWAuth() && (TextUtils.isEmpty(mUsername) ||
                (TextUtils.isEmpty(mPassword) && mTransientAuthPW == null))) {
            return R.string.password;
        }
        return 0;
    }

    @NonNull
    @Override
    public String toString() {
        return mName;
    }

    public String getUUIDString() {
        return mUuid.toString().toLowerCase(Locale.ENGLISH);
    }

    private boolean usesExtraProxyOptions() {
        if (mUseCustomConfig && mCustomConfigOptions != null && mCustomConfigOptions.contains("http-proxy-option "))
            return true;
        for (Connection c : mConnections)
            if (c.usesExtraProxyOptions())
                return true;
        return false;
    }
}




