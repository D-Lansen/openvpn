package de.blinkt.openvpn.core;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.Vector;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

import de.blinkt.openvpn.R;

public class OpenVPNThread implements Runnable {
    private static final String DUMP_PATH_STRING = "Dump path: ";
    public static final int M_FATAL = (1 << 4);
    public static final int M_NONFATAL = (1 << 5);
    public static final int M_WARN = (1 << 6);
    public static final int M_DEBUG = (1 << 7);
    private final FutureTask<OutputStream> mStreamFuture;
    private OutputStream mOutputStream;

    private final String[] mArgv;
    private Process mProcess;
    private final String mNativeDir;
    private final String mTmpDir;
    private final OpenVPNService mService;
    private String mDumpPath;
    private boolean mNoProcessExitStatus = false;

    private static final String MINIPIEVPN = "pie_openvpn";

    private static String writeMiniVPN(Context context) {
        String nativeAPI = NativeUtils.getNativeAPI();
        /* Q does not allow executing binaries written in temp directory anymore */
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P){
            return new File(context.getApplicationInfo().nativeLibraryDir, "libovpnexec.so").getPath();
        }

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
        Log.e("miniVpn:", binaryName);
        args.add(binaryName);
        args.add("--config");
        args.add("stdin");
        return args.toArray(new String[0]);
    }

    private static boolean writeMiniVPNBinary(Context context, String abi, File mVpnOut) {
        try {
            InputStream mVpn;
            try {
                mVpn = context.getAssets().open(MINIPIEVPN + "." + abi);
            } catch (IOException err) {
                VpnStatus.logInfo("Failed getting assets for architecture " + abi);
                return false;
            }

            FileOutputStream fout = new FileOutputStream(mVpnOut);

            byte[] buf = new byte[4096];

            int lenread = mVpn.read(buf);
            while (lenread > 0) {
                fout.write(buf, 0, lenread);
                lenread = mVpn.read(buf);
            }
            fout.close();

            if (!mVpnOut.setExecutable(true)) {
                VpnStatus.logError("Failed to make OpenVPN executable");
                return false;
            }

            return true;
        } catch (IOException e) {
            VpnStatus.logException(e);
            return false;
        }

    }

    public OpenVPNThread(OpenVPNService service, String nativeLibraryDir, String tmpdir) {
        mArgv = buildOpenvpnArgv(service);
        mNativeDir = nativeLibraryDir;
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
          int exitValue = 0;
            try {
                if (mProcess != null)
                    exitValue = mProcess.waitFor();
            } catch (IllegalThreadStateException ite) {
                VpnStatus.logError("Illegal Thread state: " + ite.getLocalizedMessage());
            } catch (InterruptedException ie) {
                VpnStatus.logError("InterruptedException: " + ie.getLocalizedMessage());
            }
            if (exitValue != 0) {
                VpnStatus.logError("Process exited with exit value " + exitValue);
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

        LinkedList<String> argvList = new LinkedList<>();

        Collections.addAll(argvList, argv);

        ProcessBuilder pb = new ProcessBuilder(argvList);
        // Hack O rama

        String lbPath = getLibraryPath(argv, pb);

        pb.environment().put("LD_LIBRARY_PATH", lbPath);
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
                String line = br.readLine();
                if (line == null)
                    return;

                if (line.startsWith(DUMP_PATH_STRING))
                    mDumpPath = line.substring(DUMP_PATH_STRING.length());

                if (Thread.interrupted()) {
                    Log.e("lichen.interrupted", "Thread.interrupted");
                    throw new InterruptedException("OpenVpn process was killed form java code");
                }
            }
        } catch (InterruptedException | IOException e) {
            VpnStatus.logException("Error reading from output of OpenVPN process", e);
            mStreamFuture.cancel(true);
            stopProcess();
        }

    }

    private String getLibraryPath(String[] argv, ProcessBuilder pb) {
        // Hack until I find a good way to get the real library path
        String appLibPath = argv[0].replaceFirst("/cache/.*$", "/lib");

        String lbPath = pb.environment().get("LD_LIBRARY_PATH");
        if (lbPath == null)
            lbPath = appLibPath;
        else
            lbPath = appLibPath + ":" + lbPath;

        if (!appLibPath.equals(mNativeDir)) {
            lbPath = mNativeDir + ":" + lbPath;
        }
        return lbPath;
    }

    public OutputStream getOpenVPNStdin() throws ExecutionException, InterruptedException {
        return mStreamFuture.get();
    }
}
