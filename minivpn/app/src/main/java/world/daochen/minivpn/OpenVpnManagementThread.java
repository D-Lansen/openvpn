package world.daochen.minivpn;

import android.annotation.SuppressLint;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Handler;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.util.Log;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.Objects;
import java.util.Vector;

public class OpenVpnManagementThread implements Runnable{
    public interface PausedStateCallback {
        boolean shouldBeRunning();
    }
    private PausedStateCallback mPauseCallback;
    private static final String TAG = "OpenVpnManagementThread";
    private final OpenVPNService mOpenVPNService;
    private final Handler mResumeHandler;
    private static final Vector<OpenVpnManagementThread> active = new Vector<>();
    private final LinkedList<FileDescriptor> mFDList = new LinkedList<>();
    private LocalSocket mSocket;
    private LocalServerSocket mServerSocket;
    private long mLastHoldRelease = 0;
    private boolean mWaitingForRelease = false;
    private final Runnable mResumeHoldRunnable = () -> {
        if (shouldBeRunning()) {
            releaseHoldCmd();
        }
    };
    public OpenVpnManagementThread(OpenVPNService openVpnService) {
        this.mOpenVPNService = openVpnService;
        mResumeHandler = new Handler(openVpnService.getMainLooper());
    }

    @Override
    public void run() {
        byte[] buffer = new byte[2048];

        String pendingInput = "";
        synchronized (active) {
            active.add(this);
        }

        try {
            // Wait for a client to connect
            mSocket = mServerSocket.accept();
            InputStream instream = mSocket.getInputStream();

            // Close the management socket after client connected
            try {
                mServerSocket.close();
            } catch (IOException e) {
                Log.e(TAG, "", e);
            }

            // Closing one of the two sockets also closes the other
            //mServerSocketLocal.close();
            managmentCommand("version 3\n");

            while (true) {

                int numbytesread = instream.read(buffer);
                if (numbytesread == -1)
                    return;

                FileDescriptor[] fds = null;
                try {
                    fds = mSocket.getAncillaryFileDescriptors();
                } catch (IOException e) {
                    Log.e(TAG, "Error reading fds from socket", e);
                }
                if (fds != null) {
                    Collections.addAll(mFDList, fds);
                }

                String input = new String(buffer, 0, numbytesread, StandardCharsets.UTF_8);
                pendingInput += input;
                pendingInput = processInput(pendingInput);

            }
        } catch (IOException e) {
            if (!Objects.equals(e.getMessage(), "socket closed") &&
                    !Objects.equals(e.getMessage(), "Connection reset by peer"))
                Log.e(TAG, "", e);
        }
        synchronized (active) {
            active.remove(this);
        }
    }

    public void setPauseCallback(PausedStateCallback callback) {
        mPauseCallback = callback;
    }

    public void signalusr1() {
        mResumeHandler.removeCallbacks(mResumeHoldRunnable);
        if (!mWaitingForRelease)
            managmentCommand("signal SIGUSR1\n");
    }

    public void reconnect() {
        signalusr1();
        releaseHold();
    }

    public void pause() {
        signalusr1();
    }

    public void resume() {
        releaseHold();
    }

    public void networkChange(boolean samenetwork) {
        if (mWaitingForRelease)
            releaseHold();
        else if (samenetwork)
            managmentCommand("network-change samenetwork\n");
        else
            managmentCommand("network-change\n");
    }

    public boolean openManagementInterface() {
        // Could take a while to open connection
        int tries = 8;

        String socketName = (mOpenVPNService.getCacheDir().getAbsolutePath() + "/" + "mgmtsocket");

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

    public boolean stopVPN(boolean replaceConnection) {
        return stopOpenVPN();
    }

    private static boolean stopOpenVPN() {
        synchronized (active) {
            boolean sendCMD = false;
            for (OpenVpnManagementThread mt : active) {
                sendCMD = mt.managmentCommand("signal SIGINT\n");
                try {
                    if (mt.mSocket != null)
                        mt.mSocket.close();
                } catch (IOException e) {
                    // Ignore close error on already closed socket
                }
            }
            return sendCMD;
        }
    }

    //! Hack O Rama 2000!
    private void protectFileDescriptor(FileDescriptor fd) {
        try {
            @SuppressLint("DiscouragedPrivateApi")
            Method getInt = FileDescriptor.class.getDeclaredMethod("getInt$");
            int fdint = (Integer) getInt.invoke(fd);
            // You can even get more evil by parsing toString() and extract the int from that :)

            boolean result = mOpenVPNService.protect(fdint);
            if (!result)
                Log.w(TAG,"Could not protect VPN socket");

            fdClose(fd);

            return;
        } catch (NoSuchMethodException | IllegalArgumentException | InvocationTargetException | IllegalAccessException | NullPointerException e) {
            Log.e(TAG,"Failed to retrieve fd from socket (" + fd + ")", e);
        }

        Log.d("Openvpn", "Failed to retrieve fd from socket: " + fd);

    }

    private void fdClose(FileDescriptor fd) {
        try {
            Os.close(fd);
        } catch (Exception e) {
            Log.e(TAG,"Failed to close fd (" + fd + ")", e);
        }
    }

    private void processNeedCommand(String argument) {
        int p1 = argument.indexOf('\'');
        int p2 = argument.indexOf('\'', p1 + 1);

        String needed = argument.substring(p1 + 1, p2);
        String extra = argument.split(":", 2)[1];

        String status = "ok";

        switch (needed) {
            case "PROTECTFD":
                FileDescriptor fdtoprotect = mFDList.pollFirst();
                protectFileDescriptor(fdtoprotect);
                break;
            case "DNSSERVER":
            case "DNS6SERVER":
                mOpenVPNService.addDNS(extra);
                break;
            case "DNSDOMAIN":
                mOpenVPNService.setDomain(extra);
                break;
            case "ROUTE": {
                String[] routeParts = extra.split(" ");

                if (routeParts.length == 5) {
                    mOpenVPNService.addRoute(routeParts[0], routeParts[1], routeParts[2], routeParts[4]);
                } else if (routeParts.length >= 3) {
                    mOpenVPNService.addRoute(routeParts[0], routeParts[1], routeParts[2], null);
                } else {
                    Log.e(TAG, "Unrecognized ROUTE cmd:" + Arrays.toString(routeParts) + " | " + argument);
                }

                break;
            }
            case "ROUTE6": {
                String[] routeParts = extra.split(" ");
                mOpenVPNService.addRouteV6(routeParts[0], routeParts[1]);
                break;
            }
            case "IFCONFIG":
                String[] ifConfigParts = extra.split(" ");
                int mtu = Integer.parseInt(ifConfigParts[2]);
                mOpenVPNService.setLocalIP(ifConfigParts[0], ifConfigParts[1], mtu, ifConfigParts[3]);
                break;
            case "IFCONFIG6":
                String[] ifconfig6parts = extra.split(" ");
                mtu = Integer.parseInt(ifconfig6parts[1]);
                mOpenVPNService.setMtu(mtu);
                mOpenVPNService.setLocalIpV6(ifconfig6parts[0]);
                break;
            case "PERSIST_TUN_ACTION":
                // check if tun cfg stayed the same
                status = mOpenVPNService.getTunReopenStatus();
                break;
            case "OPENTUN":
                if (sendTunFD(needed, extra))
                    return;
                else
                    status = "cancel";
                // This not nice or anything but setFileDescriptors accepts only FilDescriptor class :(

                break;
            case "HTTPPROXY":
                String[] httpproxy = extra.split(" ");
                if (httpproxy.length == 2) {
                    mOpenVPNService.addHttpProxy(httpproxy[0], Integer.parseInt(httpproxy[1]));
                } else {
                    Log.e(TAG,"Unrecognized HTTPPROXY cmd: " + Arrays.toString(httpproxy) + " | " + argument);
                }
                break;
            default:
                Log.e(TAG, "Unknown needok command " + argument);
                return;
        }

        String cmd = String.format("needok '%s' %s\n", needed, status);
        managmentCommand(cmd);
    }

    private String processInput(String pendingInput) {
        while (pendingInput.contains("\n")) {
            String[] tokens = pendingInput.split("\\r?\\n", 2);
            processCommand(tokens[0]);
            if (tokens.length == 1)
                // No second part, newline was at the end
                pendingInput = "";
            else
                pendingInput = tokens[1];
        }
        return pendingInput;
    }

    private void processCommand(String command) {
        Log.e("lichen", "processCommand:"+command );
        if (command.startsWith(">") && command.contains(":")) {
            String[] parts = command.split(":", 2);
            String cmd = parts[0].substring(1);
            String argument = parts[1];
            switch (cmd) {
                case "INFO":
                    /* Ignore greeting from management */
                    return;
                case "HOLD":
                    handleHold(argument);
                    break;
                case "NEED-OK":
                    processNeedCommand(argument);
                    break;
                case "PROXY":
                    managmentCommand("proxy NONE\n");
                    break;
                case "STATE":
                case "PASSWORD":
                case "LOG":
                case "BYTECOUNT":
                case "PK_SIGN":
                case "INFOMSG":
                    break;
                default:
                    Log.w(TAG, "MGMT: Got unrecognized command" + command);
                    Log.i(TAG, "Got unrecognized command" + command);
                    break;
            }
        } else if (command.startsWith("SUCCESS:")) {
            Log.i(TAG, "SUCCESS:"+command );
            /* Ignore this kind of message todo */
        } else if (command.startsWith("PROTECTFD:")) {
            FileDescriptor fd = mFDList.pollFirst();
            if (fd != null) {
                protectFileDescriptor(fd);
            }
        } else {
            Log.w(TAG, "MGMT: Got unrecognized line from management:" + command);
        }
    }

    private void releaseHoldCmd() {
        mResumeHandler.removeCallbacks(mResumeHoldRunnable);
        if ((System.currentTimeMillis() - mLastHoldRelease) < 5000) {
            try {
                Thread.sleep(3000);
            } catch (InterruptedException ignored) {
            }
        }
        mWaitingForRelease = false;
        mLastHoldRelease = System.currentTimeMillis();
        managmentCommand("hold release\n");
        managmentCommand("bytecount 2\n");
        managmentCommand("state on\n");
        //managmentCommand("log on all\n");
    }

    public void releaseHold() {
        if (mWaitingForRelease)
            releaseHoldCmd();
    }

    private boolean shouldBeRunning() {
        if (mPauseCallback == null)
            return false;
        else
            return mPauseCallback.shouldBeRunning();
    }

    private void handleHold(String argument) {
        mWaitingForRelease = true;
        int waitTime = Integer.parseInt(argument.split(":")[1]);
        if (shouldBeRunning()) {
            mResumeHandler.postDelayed(mResumeHoldRunnable, waitTime * 1000L);
            if (waitTime > 5)
                Log.i(TAG,"Waiting "+waitTime+" seconds between connection attempt");
            else
                Log.d(TAG,"Waiting "+waitTime+" seconds between connection attempt");
        }
    }


    /**
     * @param cmd command to write to management socket
     * @return true if command have been sent
     */
    public boolean managmentCommand(String cmd) {
        try {
            if (mSocket != null && mSocket.getOutputStream() != null) {
                mSocket.getOutputStream().write(cmd.getBytes());
                mSocket.getOutputStream().flush();
                return true;
            }
        } catch (IOException e) {
            // Ignore socket stack traces
        }
        return false;
    }

    @SuppressLint("DiscouragedPrivateApi")
    private boolean sendTunFD(String needed, String extra) {
        if (!extra.equals("tun")) {
            // We only support tun
            Log.e(TAG, "Device type %s requested, but only tun is possible with the Android API, sorry!" + extra);
            return false;
        }
        ParcelFileDescriptor pfd = mOpenVPNService.openTun();
        if (pfd == null)
            return false;

        Method setInt;
        int fdint = pfd.getFd();
        try {
            setInt = FileDescriptor.class.getDeclaredMethod("setInt$", int.class);
            FileDescriptor fdtosend = new FileDescriptor();

            setInt.invoke(fdtosend, fdint);

            FileDescriptor[] fds = {fdtosend};
            mSocket.setFileDescriptorsForSend(fds);

            // Trigger a send so we can close the fd on our side of the channel
            // The API documentation fails to mention that it will not reset the file descriptor to
            // be send and will happily send the file descriptor on every write ...
            String cmd = String.format("needok '%s' %s\n", needed, "ok");
            managmentCommand(cmd);

            // Set the FileDescriptor to null to stop this mad behavior
            mSocket.setFileDescriptorsForSend(null);

            pfd.close();

            return true;
        } catch (NoSuchMethodException | IllegalArgumentException | InvocationTargetException |
                 IOException | IllegalAccessException exp) {
            Log.e(TAG, "Could not send fd over socket", exp);
        }

        return false;
    }

    public void sendCRResponse(String response) {
        managmentCommand("cr-response " + response + "\n");
    }

}
