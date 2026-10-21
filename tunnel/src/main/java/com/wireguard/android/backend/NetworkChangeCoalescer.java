/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import com.wireguard.util.NonNullForAll;

/**
 * Collapses a burst of underlying-network callbacks into one signature change.
 * The owner restarts a short timer on every {@code true} return from {@link #observe}
 * and calls {@link #consume} when the timer fires, so only the last signature in the
 * burst is acted on. A signature of {@code "none"} means no usable network.
 */
@NonNullForAll
final class NetworkChangeCoalescer {
    static final String NO_NETWORK = "none";

    private String committed = "";
    private String scheduled = "";
    private boolean hasScheduled;

    void baseline(final String signature) {
        committed = signature;
        scheduled = "";
        hasScheduled = false;
    }

    /**
     * @return {@code true} when {@code signature} differs from the signature already
     * waiting for the debounce timer, and the timer should be restarted
     */
    boolean observe(final String signature) {
        if (hasScheduled && signature.equals(scheduled))
            return false;
        if (!hasScheduled && signature.equals(committed))
            return false;
        scheduled = signature;
        hasScheduled = true;
        return true;
    }

    /**
     * @return the signature to act on, or {@code ""} when nothing changed
     */
    String consume() {
        if (!hasScheduled)
            return "";
        final String target = scheduled;
        hasScheduled = false;
        scheduled = "";
        if (target.equals(committed))
            return "";
        committed = target;
        return target;
    }

    static boolean shouldSendKeepalive(final boolean enabled, final String signature) {
        return enabled && !signature.isEmpty() && !NO_NETWORK.equals(signature);
    }
}
