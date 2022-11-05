/*
 * Copyright (c) 2012-2016 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.core;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Vector;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.regex.Pattern;

import de.blinkt.openvpn.R;

public class OpenVPNThread implements Runnable {
    private static final String DUMP_PATH_STRING = "Dump path: ";
    @SuppressLint("SdCardPath")
    private static final String TAG = "OpenVPN";
    // 1380308330.240114 18000002 Send to HTTP proxy: 'X-Online-Host: bla.blabla.com'
    private static final Pattern LOG_PATTERN = Pattern.compile("(\\d+).(\\d+) ([0-9a-f])+ (.*)");
    public static final int M_FATAL = (1 << 4);
    public static final int M_NONFATAL = (1 << 5);
    public static final int M_WARN = (1 << 6);
    public static final int M_DEBUG = (1 << 7);
    private final FutureTask<OutputStream> mStreamFuture;
    private OutputStream mOutputStream;

    private String[] mArgv;
    private Process mProcess;
    private String mNativeDir;
    private String mTmpDir;
    private OpenVPNService mService;
    private String mDumpPath;
    private boolean mNoProcessExitStatus = false;

    private static final String MINIPIEVPN = "pie_openvpn";

    private static String writeMiniVPN(Context context) {
        String nativeAPI = NativeUtils.getNativeAPI();
        /* Q does not allow executing binaries written in temp directory anymore */
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            return new File(context.getApplicationInfo().nativeLibraryDir, "libovpnexec.so").getPath();

        String[] abis = Build.SUPPORTED_ABIS;

        if (!nativeAPI.equals(abis[0])) {
            VpnStatus.logWarning(R.string.abi_mismatch, Arrays.toString(abis), nativeAPI);
            abis = new String[]{nativeAPI};
        }

        for (String abi : abis) {

            File vpnExecutable = new File(context.getCacheDir(), "c_" + MINIPIEVPN + "." + abi);
            if ((vpnExecutable.exists() && vpnExecutable.canExecute()) || writeMiniVPNBinary(context, abi, vpnExecutable)) {
                return vpnExecutable.getPath();
            }
        }

        throw new RuntimeException("Cannot find any executable for this device's ABIs " + Arrays.toString(abis));
    }

    public static String[] buildOpenvpnArgv(Context c) {
        Vector<String> args = new Vector<>();

        String binaryName = writeMiniVPN(c);
        // Add fixed paramenters
        //args.add("/data/data/de.blinkt.openvpn/lib/openvpn");

        args.add(binaryName);

        args.add("--config");
        args.add("stdin");

        return args.toArray(new String[0]);
    }

    private static boolean writeMiniVPNBinary(Context context, String abi, File mvpnout) {
        try {
            InputStream mvpn;

            try {
                mvpn = context.getAssets().open(MINIPIEVPN + "." + abi);
            } catch (IOException errabi) {
                VpnStatus.logInfo("Failed getting assets for architecture " + abi);
                return false;
            }


            FileOutputStream fout = new FileOutputStream(mvpnout);

            byte[] buf = new byte[4096];

            int lenread = mvpn.read(buf);
            while (lenread > 0) {
                fout.write(buf, 0, lenread);
                lenread = mvpn.read(buf);
            }
            fout.close();

            if (!mvpnout.setExecutable(true)) {
                VpnStatus.logError("Failed to make OpenVPN executable");
                return false;
            }


            return true;
        } catch (IOException e) {
            VpnStatus.logException(e);
            return false;
        }

    }

    public OpenVPNThread(OpenVPNService service, String nativelibdir, String tmpdir) {
        mArgv = buildOpenvpnArgv(service);
        mNativeDir = nativelibdir;
        mTmpDir = tmpdir;
        mService = service;
        mStreamFuture = new FutureTask<>(() -> mOutputStream);
    }

    public void stopProcess() {
        mProcess.destroy();
    }

    void setReplaceConnection() {
        mNoProcessExitStatus = true;
    }

    @Override
    public void run() {
        try {
            startOpenVPNThreadArgs(mArgv);
        } catch (Exception e) {
            VpnStatus.logException("Starting OpenVPN Thread", e);
        } finally {
            int exitvalue = 0;
            try {
                if (mProcess != null)
                    exitvalue = mProcess.waitFor();
            } catch (IllegalThreadStateException ite) {
                VpnStatus.logError("Illegal Thread state: " + ite.getLocalizedMessage());
            } catch (InterruptedException ie) {
                VpnStatus.logError("InterruptedException: " + ie.getLocalizedMessage());
            }
            if (exitvalue != 0) {
                VpnStatus.logError("Process exited with exit value " + exitvalue);
            }

            if (!mNoProcessExitStatus)
                VpnStatus.updateStateString("NOPROCESS", "No process running.", R.string.state_noprocess, ConnectionStatus.LEVEL_NOTCONNECTED);

            if (mDumpPath != null) {
                VpnStatus.logError(R.string.minidump_generated);
            }

            if (!mNoProcessExitStatus)
                mService.openvpnStopped();
        }
    }

    private void startOpenVPNThreadArgs(String[] argv) {

        LinkedList<String> argvlist = new LinkedList<String>();

        Collections.addAll(argvlist, argv);

        ProcessBuilder pb = new ProcessBuilder(argvlist);
        // Hack O rama

        String lbpath = genLibraryPath(argv, pb);

        pb.environment().put("LD_LIBRARY_PATH", lbpath);
        pb.environment().put("TMPDIR", mTmpDir);

        pb.redirectErrorStream(true);
        try {
            mProcess = pb.start();
            // Close the output, since we don't need it

            InputStream in = mProcess.getInputStream();
            OutputStream out = mProcess.getOutputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(in));

            mOutputStream = out;
            mStreamFuture.run();

            while (true) {
                String logline = br.readLine();
                if (logline == null)
                    return;

                if (logline.startsWith(DUMP_PATH_STRING))
                    mDumpPath = logline.substring(DUMP_PATH_STRING.length());

                if (Thread.interrupted()) {
                    throw new InterruptedException("OpenVpn process was killed form java code");
                }
            }
        } catch (InterruptedException | IOException e) {
            VpnStatus.logException("Error reading from output of OpenVPN process", e);
            mStreamFuture.cancel(true);
            stopProcess();
        }

    }

    private String genLibraryPath(String[] argv, ProcessBuilder pb) {
        // Hack until I find a good way to get the real library path
        String applibpath = argv[0].replaceFirst("/cache/.*$", "/lib");

        String lbpath = pb.environment().get("LD_LIBRARY_PATH");
        if (lbpath == null)
            lbpath = applibpath;
        else
            lbpath = applibpath + ":" + lbpath;

        if (!applibpath.equals(mNativeDir)) {
            lbpath = mNativeDir + ":" + lbpath;
        }
        return lbpath;
    }

    public OutputStream getOpenVPNStdin() throws ExecutionException, InterruptedException {
        return mStreamFuture.get();
    }
}
