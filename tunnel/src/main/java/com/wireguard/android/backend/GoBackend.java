/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;
import android.util.Log;

import com.wireguard.android.backend.BackendException.Reason;
import com.wireguard.android.backend.Tunnel.State;
import com.wireguard.android.util.SharedLibraryLoader;
import com.wireguard.config.Config;
import com.wireguard.config.InetEndpoint;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Peer;
import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;
import com.wireguard.util.NonNullForAll;

import java.net.InetAddress;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import androidx.annotation.Nullable;
import androidx.collection.ArraySet;

/**
 * Implementation of {@link Backend} that uses the wireguard-go userspace implementation to provide
 * WireGuard tunnels.
 */
@NonNullForAll
public final class GoBackend implements Backend {
    private static final int DNS_RESOLUTION_RETRIES = 10;
    private static final String TAG = "WireGuard/GoBackend";
    @Nullable private static AlwaysOnCallback alwaysOnCallback;
    private static CompletableFuture<VpnService> vpnService = new CompletableFuture<>();
    private final Context context;
    @Nullable private Config currentConfig;
    @Nullable private Tunnel currentTunnel;
    private int currentTunnelHandle = -1;
    private final Object wgLock = new Object();
    @Nullable private ConnectivityManager.NetworkCallback networkCallback;
    private volatile int networkEpoch;

    /**
     * Public constructor for GoBackend.
     *
     * @param context An Android {@link Context}
     */
    public GoBackend(final Context context) {
        SharedLibraryLoader.loadSharedLibrary(context, "wg-go");
        this.context = context;
    }

    /**
     * Set a {@link AlwaysOnCallback} to be invoked when {@link VpnService} is started by the
     * system's Always-On VPN mode.
     *
     * @param cb Callback to be invoked
     */
    public static void setAlwaysOnCallback(final AlwaysOnCallback cb) {
        alwaysOnCallback = cb;
    }

    @Nullable private static native String wgGetConfig(int handle);

    private static native int wgGetSocketV4(int handle);

    private static native int wgGetSocketV6(int handle);

    private static native void wgTurnOff(int handle);

    @Nullable private static native String wgBindUpdate(int handle);

    @Nullable private static native String wgSendKeepalivesToPeersWithCurrentKeypair(int handle);

    private static native int wgTurnOn(String ifName, int tunFd, String settings);

    private static native String wgVersion();

    /**
     * Method to get the names of running tunnels.
     *
     * @return A set of string values denoting names of running tunnels.
     */
    @Override
    public Set<String> getRunningTunnelNames() {
        if (currentTunnel != null) {
            final Set<String> runningTunnels = new ArraySet<>();
            runningTunnels.add(currentTunnel.getName());
            return runningTunnels;
        }
        return Collections.emptySet();
    }

    /**
     * Get the associated {@link State} for a given {@link Tunnel}.
     *
     * @param tunnel The tunnel to examine the state of.
     * @return {@link State} associated with the given tunnel.
     */
    @Override
    public State getState(final Tunnel tunnel) {
        return currentTunnel == tunnel ? State.UP : State.DOWN;
    }

    /**
     * Get the associated {@link Statistics} for a given {@link Tunnel}.
     *
     * @param tunnel The tunnel to retrieve statistics for.
     * @return {@link Statistics} associated with the given tunnel.
     */
    @Override
    public Statistics getStatistics(final Tunnel tunnel) {
        final Statistics stats = new Statistics();
        if (tunnel != currentTunnel || currentTunnelHandle == -1)
            return stats;
        final String config = wgGetConfig(currentTunnelHandle);
        if (config == null)
            return stats;
        Key key = null;
        long rx = 0;
        long tx = 0;
        long latestHandshakeMSec = 0;
        for (final String line : config.split("\\n")) {
            if (line.startsWith("public_key=")) {
                if (key != null)
                    stats.add(key, rx, tx, latestHandshakeMSec);
                rx = 0;
                tx = 0;
                latestHandshakeMSec = 0;
                try {
                    key = Key.fromHex(line.substring(11));
                } catch (final KeyFormatException ignored) {
                    key = null;
                }
            } else if (line.startsWith("rx_bytes=")) {
                if (key == null)
                    continue;
                try {
                    rx = Long.parseLong(line.substring(9));
                } catch (final NumberFormatException ignored) {
                    rx = 0;
                }
            } else if (line.startsWith("tx_bytes=")) {
                if (key == null)
                    continue;
                try {
                    tx = Long.parseLong(line.substring(9));
                } catch (final NumberFormatException ignored) {
                    tx = 0;
                }
            } else if (line.startsWith("last_handshake_time_sec=")) {
                if (key == null)
                    continue;
                try {
                    latestHandshakeMSec += Long.parseLong(line.substring(24)) * 1000;
                } catch (final NumberFormatException ignored) {
                    latestHandshakeMSec = 0;
                }
            } else if (line.startsWith("last_handshake_time_nsec=")) {
                if (key == null)
                    continue;
                try {
                    latestHandshakeMSec += Long.parseLong(line.substring(25)) / 1000000;
                } catch (final NumberFormatException ignored) {
                    latestHandshakeMSec = 0;
                }
            }
        }
        if (key != null)
            stats.add(key, rx, tx, latestHandshakeMSec);
        return stats;
    }

    /**
     * Get the version of the underlying wireguard-go library.
     *
     * @return {@link String} value of the version of the wireguard-go library.
     */
    @Override
    public String getVersion() {
        return wgVersion();
    }

    /**
     * Determines if the service is running in always-on VPN mode.
     * @return {@link boolean} whether the service is running in always-on VPN mode.
     */
    @Override
    public boolean isAlwaysOn() throws ExecutionException, InterruptedException, TimeoutException {
        return vpnService.get(0, TimeUnit.NANOSECONDS).isAlwaysOn();
    }

    /**
     * Determines if the service is running in always-on VPN lockdown mode.
     * @return {@link boolean} whether the service is running in always-on VPN lockdown mode.
     */
    @Override
    public boolean isLockdownEnabled() throws ExecutionException, InterruptedException, TimeoutException {
        return vpnService.get(0, TimeUnit.NANOSECONDS).isLockdownEnabled();
    }

    /**
     * Change the state of a given {@link Tunnel}, optionally applying a given {@link Config}.
     *
     * @param tunnel The tunnel to control the state of.
     * @param state  The new state for this tunnel. Must be {@code UP}, {@code DOWN}, or
     *               {@code TOGGLE}.
     * @param config The configuration for this tunnel, may be null if state is {@code DOWN}.
     * @return {@link State} of the tunnel after state changes are applied.
     * @throws Exception Exception raised while changing tunnel state.
     */
    @Override
    public State setState(final Tunnel tunnel, State state, @Nullable final Config config) throws Exception {
        final State originalState = getState(tunnel);

        if (state == State.TOGGLE)
            state = originalState == State.UP ? State.DOWN : State.UP;
        if (state == originalState && tunnel == currentTunnel && config == currentConfig)
            return originalState;
        if (state == State.UP) {
            final Config originalConfig = currentConfig;
            final Tunnel originalTunnel = currentTunnel;
            if (currentTunnel != null)
                setStateInternal(currentTunnel, null, State.DOWN);
            try {
                setStateInternal(tunnel, config, state);
            } catch (final Exception e) {
                if (originalTunnel != null)
                    setStateInternal(originalTunnel, originalConfig, State.UP);
                throw e;
            }
        } else if (state == State.DOWN && tunnel == currentTunnel) {
            setStateInternal(tunnel, null, State.DOWN);
        }
        return getState(tunnel);
    }

    private void setStateInternal(final Tunnel tunnel, @Nullable final Config config, final State state)
            throws Exception {
        Log.i(TAG, "Bringing tunnel " + tunnel.getName() + ' ' + state);

        if (state == State.UP) {
            if (config == null)
                throw new BackendException(Reason.TUNNEL_MISSING_CONFIG);

            if (VpnService.prepare(context) != null)
                throw new BackendException(Reason.VPN_NOT_AUTHORIZED);

            final VpnService service;
            if (!vpnService.isDone()) {
                Log.d(TAG, "Requesting to start VpnService");
                context.startService(new Intent(context, VpnService.class));
            }

            try {
                service = vpnService.get(2, TimeUnit.SECONDS);
            } catch (final TimeoutException e) {
                final Exception be = new BackendException(Reason.UNABLE_TO_START_VPN);
                be.initCause(e);
                throw be;
            }
            service.setOwner(this);

            if (currentTunnelHandle != -1) {
                Log.w(TAG, "Tunnel already up");
                return;
            }


            dnsRetry: for (int i = 0; i < DNS_RESOLUTION_RETRIES; ++i) {
                // Pre-resolve IPs so they're cached when building the userspace string
                for (final Peer peer : config.getPeers()) {
                    final InetEndpoint ep = peer.getEndpoint().orElse(null);
                    if (ep == null)
                        continue;
                    if (ep.getResolved().orElse(null) == null) {
                        if (i < DNS_RESOLUTION_RETRIES - 1) {
                            Log.w(TAG, "DNS host \"" + ep.getHost() + "\" failed to resolve; trying again");
                            Thread.sleep(1000);
                            continue dnsRetry;
                        } else
                            throw new BackendException(Reason.DNS_RESOLUTION_FAILURE, ep.getHost());
                    }
                }
                break;
            }

            // Build config
            final String goConfig = config.toWgUserspaceString();

            // Create the vpn tunnel with android API
            final VpnService.Builder builder = service.getBuilder();
            builder.setSession(tunnel.getName());

            for (final String excludedApplication : config.getInterface().getExcludedApplications())
                builder.addDisallowedApplication(excludedApplication);

            for (final String includedApplication : config.getInterface().getIncludedApplications())
                builder.addAllowedApplication(includedApplication);

            for (final InetNetwork addr : config.getInterface().getAddresses())
                builder.addAddress(addr.getAddress(), addr.getMask());

            for (final InetAddress addr : config.getInterface().getDnsServers())
                builder.addDnsServer(addr.getHostAddress());

            for (final String dnsSearchDomain : config.getInterface().getDnsSearchDomains())
                builder.addSearchDomain(dnsSearchDomain);

            boolean sawDefaultRoute = false;
            for (final Peer peer : config.getPeers()) {
                for (final InetNetwork addr : peer.getAllowedIps()) {
                    if (addr.getMask() == 0)
                        sawDefaultRoute = true;
                    builder.addRoute(addr.getAddress(), addr.getMask());
                }
            }

            // "Kill-switch" semantics
            if (!(sawDefaultRoute && config.getPeers().size() == 1)) {
                builder.allowFamily(OsConstants.AF_INET);
                builder.allowFamily(OsConstants.AF_INET6);
            }

            builder.setMtu(config.getInterface().getMtu().orElse(1280));

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                builder.setMetered(false);
            service.setUnderlyingNetworks(null);

            builder.setBlocking(true);
            try (final ParcelFileDescriptor tun = builder.establish()) {
                if (tun == null)
                    throw new BackendException(Reason.TUN_CREATION_ERROR);
                Log.d(TAG, "Go backend " + wgVersion());
                currentTunnelHandle = wgTurnOn(tunnel.getName(), tun.detachFd(), goConfig);
            }
            if (currentTunnelHandle < 0)
                throw new BackendException(Reason.GO_ACTIVATION_ERROR_CODE, currentTunnelHandle);

            currentTunnel = tunnel;
            currentConfig = config;

            service.protect(wgGetSocketV4(currentTunnelHandle));
            service.protect(wgGetSocketV6(currentTunnelHandle));
            startNetworkChangeMonitor(tunnel.getName());
        } else {
            stopNetworkChangeMonitor();
            synchronized (wgLock) {
                if (currentTunnelHandle == -1) {
                    Log.w(TAG, "Tunnel already down");
                    return;
                }
                final int handleToClose = currentTunnelHandle;
                currentTunnel = null;
                currentTunnelHandle = -1;
                currentConfig = null;
                wgTurnOff(handleToClose);
            }
            try {
                vpnService.get(0, TimeUnit.NANOSECONDS).stopSelf();
            } catch (final TimeoutException ignored) { }
        }

        tunnel.onStateChange(state);
    }

    /**
     * Start watching the underlying networks so that one keepalive is sent when they change, as
     * wireguard-apple does with wgBumpSockets. Any previous monitor is stopped first.
     * {@code registerDefaultNetworkCallback} would report this VPN once it becomes the default, so
     * this registers a listen-only {@link ConnectivityManager#registerNetworkCallback} for networks
     * with {@code NET_CAPABILITY_INTERNET} and {@code NET_CAPABILITY_NOT_VPN} instead.
     * Networks already present at registration are not a change. A newly available network sends
     * a keepalive; a lost network sends one only if another underlying network remains.
     * PersistentKeepalive is not changed.
     *
     * @param tunnelName The name of the tunnel that was just brought up. Keepalives are only sent
     *                   while it is still the current tunnel.
     */
    private void startNetworkChangeMonitor(final String tunnelName) {
        stopNetworkChangeMonitor();
        final ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) {
            Log.e(TAG, "Tunnel " + tunnelName + ": ConnectivityManager unavailable; network-change keepalive will not run");
            return;
        }
        final int epoch = ++networkEpoch;
        final Set<Network> seen = new ArraySet<>();
        for (final Network network : cm.getAllNetworks()) {
            final NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            if (caps != null
                    && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))
                seen.add(network);
        }
        final int present = seen.size();
        final ConnectivityManager.NetworkCallback callback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(final Network network) {
                if (epoch != networkEpoch || !seen.add(network))
                    return;
                sendNetworkChangeKeepalive(tunnelName, "onAvailable " + network);
            }

            @Override
            public void onLost(final Network network) {
                if (epoch != networkEpoch || !seen.remove(network))
                    return;
                if (seen.isEmpty()) {
                    Log.i(TAG, "Tunnel " + tunnelName + ": no underlying network left after losing " + network + "; not sending keepalive");
                    return;
                }
                sendNetworkChangeKeepalive(tunnelName, "onLost " + network);
            }
        };
        final NetworkRequest request = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build();
        try {
            cm.registerNetworkCallback(request, callback);
            networkCallback = callback;
            Log.i(TAG, "Tunnel " + tunnelName + ": watching underlying networks for one-shot keepalive (" + present + " present)");
        } catch (final RuntimeException e) {
            Log.e(TAG, "Tunnel " + tunnelName + ": failed to register network callback: " + e.getMessage(), e);
        }
    }

    /**
     * Stop the monitor started by {@link #startNetworkChangeMonitor(String)}, if any. Callbacks
     * from an older registration are ignored from then on. Does nothing if no monitor is
     * registered.
     */
    private void stopNetworkChangeMonitor() {
        networkEpoch++;
        final ConnectivityManager.NetworkCallback callback = networkCallback;
        networkCallback = null;
        if (callback == null)
            return;
        final ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null)
            return;
        try {
            cm.unregisterNetworkCallback(callback);
        } catch (final RuntimeException e) {
            Log.w(TAG, "Failed to unregister network callback: " + e.getMessage(), e);
        }
    }

    /**
     * Rebind the UDP sockets of the current tunnel and send one keepalive to each peer that has a
     * current session. {@code wgBindUpdate} replaces the sockets, so each new socket is passed to
     * {@link VpnService#protect(int)} before {@code wgSendKeepalivesToPeersWithCurrentKeypair}
     * runs; otherwise the keepalive would be routed into the tunnel. Nothing is sent if the tunnel
     * is down or is no longer {@code tunnelName}, if no socket is left after the rebind, or if
     * rebinding or protecting fails. Failures are logged.
     *
     * @param tunnelName The name of the tunnel the monitor was started for.
     * @param why        The network event that caused this call, used in log messages.
     */
    private void sendNetworkChangeKeepalive(final String tunnelName, final String why) {
        synchronized (wgLock) {
            if (currentTunnelHandle < 0 || currentTunnel == null || !tunnelName.equals(currentTunnel.getName()))
                return;
            final int handle = currentTunnelHandle;
            Log.i(TAG, "Tunnel " + tunnelName + ": underlying network changed (" + why + "); rebinding UDP sockets and sending one keepalive to each peer with a current session");
            final String bindError = wgBindUpdate(handle);
            if (bindError != null) {
                Log.e(TAG, "Tunnel " + tunnelName + ": BindUpdate failed after " + why + ": " + bindError);
                return;
            }
            final VpnService service;
            try {
                service = vpnService.get(0, TimeUnit.NANOSECONDS);
            } catch (final Exception e) {
                Log.e(TAG, "Tunnel " + tunnelName + ": VpnService is not running; not sending keepalive after " + why, e);
                return;
            }
            final int fd4 = wgGetSocketV4(handle);
            final int fd6 = wgGetSocketV6(handle);
            if (fd4 < 0 && fd6 < 0) {
                Log.e(TAG, "Tunnel " + tunnelName + ": no UDP socket after rebind (" + why + "); not sending keepalive");
                return;
            }
            if (fd4 < 0)
                Log.w(TAG, "Tunnel " + tunnelName + ": no IPv4 UDP socket after rebind (" + why + ")");
            else if (!service.protect(fd4)) {
                Log.e(TAG, "Tunnel " + tunnelName + ": VpnService.protect failed for IPv4 socket fd " + fd4 + " after " + why + "; not sending keepalive");
                return;
            }
            if (fd6 < 0)
                Log.w(TAG, "Tunnel " + tunnelName + ": no IPv6 UDP socket after rebind (" + why + ")");
            else if (!service.protect(fd6)) {
                Log.e(TAG, "Tunnel " + tunnelName + ": VpnService.protect failed for IPv6 socket fd " + fd6 + " after " + why + "; not sending keepalive");
                return;
            }
            final String sendError = wgSendKeepalivesToPeersWithCurrentKeypair(handle);
            if (sendError != null) {
                Log.e(TAG, "Tunnel " + tunnelName + ": keepalive failed after " + why + ": " + sendError);
                return;
            }
            Log.i(TAG, "Tunnel " + tunnelName + ": sent one network-change keepalive to each peer with a current session");
        }
    }

    /**
     * Callback for {@link GoBackend} that is invoked when {@link VpnService} is started by the
     * system's Always-On VPN mode.
     */
    public interface AlwaysOnCallback {
        void alwaysOnTriggered();
    }

    /**
     * {@link android.net.VpnService} implementation for {@link GoBackend}
     */
    public static class VpnService extends android.net.VpnService {
        @Nullable private GoBackend owner;

        public Builder getBuilder() {
            return new Builder();
        }

        @Override
        public void onCreate() {
            vpnService.complete(this);
            super.onCreate();
        }

        @Override
        public void onDestroy() {
            if (owner != null) {
                owner.stopNetworkChangeMonitor();
                final Tunnel tunnel = owner.currentTunnel;
                if (tunnel != null) {
                    synchronized (owner.wgLock) {
                        if (owner.currentTunnelHandle != -1)
                            wgTurnOff(owner.currentTunnelHandle);
                        owner.currentTunnel = null;
                        owner.currentTunnelHandle = -1;
                        owner.currentConfig = null;
                    }
                    tunnel.onStateChange(State.DOWN);
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                vpnService = vpnService.newIncompleteFuture();
            else
                vpnService = new CompletableFuture<>();
            super.onDestroy();
        }

        @Override
        public int onStartCommand(@Nullable final Intent intent, final int flags, final int startId) {
            vpnService.complete(this);
            if (intent == null || intent.getComponent() == null || !intent.getComponent().getPackageName().equals(getPackageName())) {
                Log.d(TAG, "Service started by Always-on VPN feature");
                if (alwaysOnCallback != null)
                    alwaysOnCallback.alwaysOnTriggered();
            }
            return super.onStartCommand(intent, flags, startId);
        }

        public void setOwner(final GoBackend owner) {
            this.owner = owner;
        }
    }
}
