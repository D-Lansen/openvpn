package world.daochen.minivpn;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Vector;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

public class OpenVPNThread extends Thread {
    private static final String TAG = "OpenVPNThread";
    private static final String DUMP_PATH_STRING = "Dump path: ";

    private final OpenVPNService mService;
    private Process mProcess;
    private String mDumpPath;
    private OutputStream mOutputStream;
    private final FutureTask<OutputStream> mStreamFuture;
    private boolean mNoProcessExitStatus = false;

    public OpenVPNThread(OpenVPNService service) {
        this.mService = service;
        mStreamFuture = new FutureTask<>(() -> mOutputStream);
    }

    public void setReplaceConnection() {
        this.mNoProcessExitStatus = true;
    }

    @Override
    public void run() {
        try {
            startOpenVPNThreadArgs();
        } catch (Exception e) {
            Log.e(TAG, "Starting OpenVPN Thread", e);
        } finally {
            int exitValue = 0;
            try {
                if (mProcess != null)
                    exitValue = mProcess.waitFor();
            } catch (IllegalThreadStateException e) {
                Log.e(TAG, "Illegal Thread state: " + e.getLocalizedMessage());
            } catch (InterruptedException e) {
                Log.e(TAG, "InterruptedException: " + e.getLocalizedMessage());
            }
            if (exitValue != 0) {
                Log.e(TAG, "Process exited with exit value " + exitValue);
            }
            if (mDumpPath != null) {
                Log.e(TAG, "Crashed unexpectedly. Please consider using the send Minidump option in the main menu");
            }
            Log.i(TAG, "No process running.");
            if (!mNoProcessExitStatus){
                mService.openvpnStopped();
            }
        }
    }

    private String getBinaryName(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return new File(context.getApplicationInfo().nativeLibraryDir, Native.getOvpnexe()).getPath();
        }
        //todo
        throw new RuntimeException("Cannot find any executable for this device's ABIs");
    }

    private String getLibraryPath(String binaryName, ProcessBuilder pb, Context context) {
        // Hack until I find a good way to get the real library path
        String appLibPath = binaryName.replaceFirst("/cache/.*$", "/lib");
        String lbPath = pb.environment().get("LD_LIBRARY_PATH");
        String nativeDir = context.getApplicationInfo().nativeLibraryDir;
        if (lbPath == null)
            lbPath = appLibPath;
        else
            lbPath = appLibPath + ":" + lbPath;

        if (!appLibPath.equals(nativeDir)) {
            lbPath = nativeDir + ":" + lbPath;
        }
        return lbPath;
    }

    private String getTmpDir() {
        String tmpDir;
        try {
            tmpDir = mService.getCacheDir().getCanonicalPath();
        } catch (IOException e) {
            e.printStackTrace();
            tmpDir = "/tmp";
        }
        return tmpDir;
    }

    public void startOpenVPNThreadArgs() {
        Vector<String> args = new Vector<>();
        String binaryName = getBinaryName(mService);
        args.add(binaryName);
        args.add("--config");
        args.add("stdin");

        ProcessBuilder pb = new ProcessBuilder(args);
        String lbPath = getLibraryPath(binaryName, pb, mService);
        String tmpDir = getTmpDir();
        //  android:extractNativeLibs="true"
        pb.environment().put("LD_LIBRARY_PATH", lbPath);
        pb.environment().put("TMPDIR", tmpDir);

        pb.redirectErrorStream(true);

        try {
            mProcess = pb.start();
            InputStream in = mProcess.getInputStream();
            OutputStream out = mProcess.getOutputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(in));

            mOutputStream = out;
            mStreamFuture.run();

            Log.i(TAG, "startOpenVPNThread");

            while (true) {
                String line = br.readLine();
                if (line == null)
                    return;

                if (line.startsWith(DUMP_PATH_STRING))
                    mDumpPath = line.substring(DUMP_PATH_STRING.length());

                if (Thread.interrupted()) {
                    throw new InterruptedException("OpenVpn process was killed form java code");
                }
            }

        } catch (IOException | InterruptedException e) {
            Log.e(TAG, "Error reading from output of OpenVPN process", e);
            mStreamFuture.cancel(true);
            mProcess.destroy();
        }

    }

    public OutputStream getOpenVPNStdin() throws ExecutionException, InterruptedException {
        return mStreamFuture.get();
    }

}
