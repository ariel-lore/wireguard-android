/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import com.wireguard.util.NonNullForAll;

import java.util.Objects;

/**
 * Picks the underlying network protected sockets should follow. Validated networks
 * outrank unvalidated ones, then ethernet, Wi-Fi, cellular, and other transports.
 * Ties break toward the higher network handle so the choice does not flap.
 */
@NonNullForAll
final class UnderlyingNetworkRank {
    static final int TRANSPORT_OTHER = 50;
    static final int TRANSPORT_BLUETOOTH = 100;
    static final int TRANSPORT_CELLULAR = 200;
    static final int TRANSPORT_WIFI = 300;
    static final int TRANSPORT_ETHERNET = 400;

    private UnderlyingNetworkRank() {
    }

    static int score(final int transportRank, final boolean validated, final boolean notMetered, final boolean suspended) {
        int score = transportRank;
        if (validated)
            score += 1000;
        if (notMetered)
            score += 20;
        if (suspended)
            score -= 500;
        return score;
    }

    static final class Candidate {
        final long handle;
        final int score;
        final String signature;

        Candidate(final long handle, final int score, final String signature) {
            this.handle = handle;
            this.score = score;
            this.signature = Objects.requireNonNull(signature, "signature");
        }
    }

    static String select(final Iterable<Candidate> candidates) {
        Candidate best = null;
        for (final Candidate candidate : candidates) {
            if (best == null
                    || candidate.score > best.score
                    || (candidate.score == best.score && candidate.handle > best.handle))
                best = candidate;
        }
        return best == null ? NetworkChangeCoalescer.NO_NETWORK : best.signature;
    }
}
