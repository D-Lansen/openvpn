package de.blinkt.openvpn.core;

import android.annotation.SuppressLint;
import android.content.Context;
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

import de.blinkt.openvpn.R;

public class OpenVpnManagementThread implements Runnable, OpenVPNManagement {

    //    public static final int ORBOT_TIMEOUT_MS = 20 * 1000;
    private static final String TAG = "openvpn";
    private static final Vector<OpenVpnManagementThread> active = new Vector<>();
    private final Handler mResumeHandler;
    private LocalSocket mSocket;
    private final OpenVPNService mOpenVPNService;
    private final LinkedList<FileDescriptor> mFDList = new LinkedList<>();
    private LocalServerSocket mServerSocket;
    private boolean mWaitingForRelease = false;
    private long mLastHoldRelease = 0;

    private pauseReason lastPauseReason = pauseReason.noNetwork;
    private PausedStateCallback mPauseCallback;
    private boolean mShuttingDown;
    private final Runnable mResumeHoldRunnable = () -> {
        if (shouldBeRunning()) {
            releaseHoldCmd();
        }
    };

    public OpenVpnManagementThread(OpenVPNService openVpnService) {
        mOpenVPNService = openVpnService;
        mResumeHandler = new Handler(openVpnService.getMainLooper());
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

    public boolean openManagementInterface(Context c) {
        // Could take a while to open connection
        int tries = 8;

        String socketName = (c.getCacheDir().getAbsolutePath() + "/" + "mgmtsocket");

        LocalSocket mServerSocketLocal = new LocalSocket();

        while (tries > 0 && !mServerSocketLocal.isBound()) {
            try {
                mServerSocketLocal.bind(new LocalSocketAddress(socketName,
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
            mServerSocket = new LocalServerSocket(mServerSocketLocal.getFileDescriptor());
            return true;
        } catch (IOException e) {
            VpnStatus.logException(e);
        }
        return false;
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

    @Override
    public void run() {
        byte[] buffer = new byte[2048];
        //	mSocket.setSoTimeout(5); // Setting a timeout cannot be that bad

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
                VpnStatus.logException(e);
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
                    VpnStatus.logException("Error reading fds from socket", e);
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
                VpnStatus.logException(e);
        }
        synchronized (active) {
            active.remove(this);
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
                VpnStatus.logWarning("Could not protect VPN socket");

            fdClose(fd);

            return;
        } catch (NoSuchMethodException | IllegalArgumentException | InvocationTargetException | IllegalAccessException | NullPointerException e) {
            VpnStatus.logException("Failed to retrieve fd from socket (" + fd + ")", e);
        }

        Log.d("Openvpn", "Failed to retrieve fd from socket: " + fd);

    }

    private void fdClose(FileDescriptor fd) {
        try {
            Os.close(fd);
        } catch (Exception e) {
            VpnStatus.logException("Failed to close fd (" + fd + ")", e);
        }
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
        //Log.i(TAG, "Line from managment" + command);
        if (command.startsWith(">") && command.contains(":")) {
            String[] parts = command.split(":", 2);
            String cmd = parts[0].substring(1);
            String argument = parts[1];
            switch (cmd) {
                case "INFO":
                    /* Ignore greeting from management */
                    return;
                case "PASSWORD":
//                    processPWCommand(argument);
                    break;
                case "HOLD":
                    handleHold(argument);
                    break;
                case "NEED-OK":
                    processNeedCommand(argument);
                    break;
                case "BYTECOUNT":
                    //processByteCount(argument);
                    break;
                case "STATE":
                    if (!mShuttingDown)
                        processState(argument);
                    break;
                case "PROXY":
                    managmentCommand("proxy NONE\n");
//                    processProxyCMD(argument);
                    break;
                case "LOG":
//                    processLogMessage(argument);
                    break;
                case "PK_SIGN":
//                    processSignCommand(argument);
                    break;
                case "INFOMSG":
//                    processInfoMessage(argument);
                    break;
                default:
                    VpnStatus.logWarning("MGMT: Got unrecognized command" + command);
                    Log.i(TAG, "Got unrecognized command" + command);
                    break;
            }
        } else if (command.startsWith("SUCCESS:")) {
            /* Ignore this kind of message todo */
        } else if (command.startsWith("PROTECTFD: ")) {
            FileDescriptor fdtoprotect = mFDList.pollFirst();
            if (fdtoprotect != null) {
                protectFileDescriptor(fdtoprotect);
            }
        } else {
            VpnStatus.logWarning("MGMT: Got unrecognized line from management:" + command);
        }
    }

    boolean shouldBeRunning() {
        if (mPauseCallback == null)
            return false;
        else
            return mPauseCallback.shouldBeRunning();
    }

    private void handleHold(String argument) {
        mWaitingForRelease = true;
        int waitTime = Integer.parseInt(argument.split(":")[1]);
        if (shouldBeRunning()) {
            if (waitTime > 1)
                VpnStatus.updateStateString("CONNECTRETRY", String.valueOf(waitTime),
                        R.string.state_waitconnectretry, ConnectionStatus.LEVEL_CONNECTING_NO_SERVER_REPLY_YET);
            mResumeHandler.postDelayed(mResumeHoldRunnable, waitTime * 1000L);
            if (waitTime > 5)
                VpnStatus.logInfo(R.string.state_waitconnectretry, String.valueOf(waitTime));
            else
                VpnStatus.logDebug(R.string.state_waitconnectretry, String.valueOf(waitTime));

        } else {
            VpnStatus.updateStatePause(lastPauseReason);
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
        managmentCommand("bytecount " + mBytecountInterval + "\n");
        managmentCommand("state on\n");
        //managmentCommand("log on all\n");
    }

    public void releaseHold() {
        if (mWaitingForRelease)
            releaseHoldCmd();
    }

    private void processState(String argument) {
        String[] args = argument.split(",", 3);
        String currentState = args[1];

        if (args[2].equals(",,"))
            VpnStatus.updateStateString(currentState, "");
        else
            VpnStatus.updateStateString(currentState, args[2]);
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
                    VpnStatus.logError("Unrecognized ROUTE cmd:" + Arrays.toString(routeParts) + " | " + argument);
                }

                break;
            }
            case "ROUTE6": {
                String[] routeParts = extra.split(" ");
                mOpenVPNService.addRoutev6(routeParts[0], routeParts[1]);
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
                mOpenVPNService.setLocalIPv6(ifconfig6parts[0]);
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
                    VpnStatus.logError("Unrecognized HTTPPROXY cmd: " + Arrays.toString(httpproxy) + " | " + argument);
                }
                break;
            default:
                Log.e(TAG, "Unknown needok command " + argument);
                return;
        }

        String cmd = String.format("needok '%s' %s\n", needed, status);
        managmentCommand(cmd);
    }

    @SuppressLint("DiscouragedPrivateApi")
    private boolean sendTunFD(String needed, String extra) {
        if (!extra.equals("tun")) {
            // We only support tun
            VpnStatus.logError(String.format("Device type %s requested, but only tun is possible with the Android API, sorry!", extra));

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
            VpnStatus.logException("Could not send fd over socket", exp);
        }

        return false;
    }

    @Override
    public void networkChange(boolean samenetwork) {
        if (mWaitingForRelease)
            releaseHold();
        else if (samenetwork)
            managmentCommand("network-change samenetwork\n");
        else
            managmentCommand("network-change\n");
    }

    @Override
    public void setPauseCallback(PausedStateCallback callback) {
        mPauseCallback = callback;
    }

    @Override
    public void sendCRResponse(String response) {
        managmentCommand("cr-response " + response + "\n");
    }

    public void signalusr1() {
        mResumeHandler.removeCallbacks(mResumeHoldRunnable);
        if (!mWaitingForRelease)
            managmentCommand("signal SIGUSR1\n");
        else
            // If signalusr1 is called update the state string
            // if there is another for stopping
            VpnStatus.updateStatePause(lastPauseReason);
    }

    public void reconnect() {
        signalusr1();
        releaseHold();
    }

    @Override
    public void pause(pauseReason reason) {
        lastPauseReason = reason;
        signalusr1();
    }

    @Override
    public void resume() {
        releaseHold();
        /* Reset the reason why we are disconnected */
        lastPauseReason = pauseReason.noNetwork;
    }

    @Override
    public boolean stopVPN(boolean replaceConnection) {
        boolean stopSucceed = stopOpenVPN();
        if (stopSucceed) {
            mShuttingDown = true;
        }
        return stopSucceed;
    }

}
