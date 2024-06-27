package world.daochen.minivpn;

import android.content.Context;
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

public class BinaryThread extends Thread {
    private static final String TAG = "BinaryThread";
    private static final String DUMP_PATH_STRING = "Dump path: ";

    private final Context mContext;
    private Process mProcess;
    private String mDumpPath;
    private OutputStream mOutputStream;
    private final FutureTask<OutputStream> mStreamFuture;
    private final String mBinaryName;

    private Handler handler;

    public interface Handler {
        void onFinally();
    }

    public void setHandler(Handler handler) {
        this.handler = handler;
    }

    public BinaryThread(Context context,String binaryName, Handler handler) {
        this.mContext = context;
        this.handler = handler;
        this.mBinaryName = binaryName;
        mStreamFuture = new FutureTask<>(() -> mOutputStream);
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
            if (handler!=null){
                handler.onFinally();
            }
        }
    }

    private String getBinaryName(Context context, String binaryName) {
        return new File(context.getApplicationInfo().nativeLibraryDir, binaryName).getPath();
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

    private String getTmpDir(Context context) {
        String tmpDir;
        try {
            tmpDir = context.getCacheDir().getCanonicalPath();
        } catch (IOException e) {
            Log.e(TAG, "IOException:" + e.getMessage());
            tmpDir = "/tmp";
        }
        return tmpDir;
    }

    public void startOpenVPNThreadArgs() {
        Vector<String> args = new Vector<>();
        String binaryName = getBinaryName(mContext, mBinaryName);
        args.add(binaryName);
        args.add("--config");
        args.add("stdin");

        ProcessBuilder pb = new ProcessBuilder(args);
        String lbPath = getLibraryPath(binaryName, pb, mContext);
        String tmpDir = getTmpDir(mContext);
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
