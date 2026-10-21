/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class UnderlyingNetworkRankTest {
    @Test
    public void no_candidates_is_no_network() {
        assertEquals(NetworkChangeCoalescer.NO_NETWORK, UnderlyingNetworkRank.select(Collections.emptyList()));
    }

    @Test
    public void validated_wifi_beats_validated_cellular() {
        final UnderlyingNetworkRank.Candidate cellular = candidate(2, UnderlyingNetworkRank.TRANSPORT_CELLULAR, true, false, false, "2:cellular:validated");
        final UnderlyingNetworkRank.Candidate wifi = candidate(1, UnderlyingNetworkRank.TRANSPORT_WIFI, true, true, false, "1:wifi:validated");
        assertTrue(wifi.score > cellular.score);
        assertEquals("1:wifi:validated", UnderlyingNetworkRank.select(Arrays.asList(cellular, wifi)));
    }

    @Test
    public void validated_cellular_beats_unvalidated_wifi() {
        final UnderlyingNetworkRank.Candidate wifi = candidate(1, UnderlyingNetworkRank.TRANSPORT_WIFI, false, true, false, "1:wifi:unvalidated");
        final UnderlyingNetworkRank.Candidate cellular = candidate(2, UnderlyingNetworkRank.TRANSPORT_CELLULAR, true, false, false, "2:cellular:validated");
        assertTrue(cellular.score > wifi.score);
        assertEquals("2:cellular:validated", UnderlyingNetworkRank.select(Arrays.asList(wifi, cellular)));
    }

    @Test
    public void equal_scores_prefer_the_higher_handle() {
        final int score = UnderlyingNetworkRank.score(UnderlyingNetworkRank.TRANSPORT_WIFI, true, true, false);
        final UnderlyingNetworkRank.Candidate low = new UnderlyingNetworkRank.Candidate(4, score, "4:wifi:validated");
        final UnderlyingNetworkRank.Candidate high = new UnderlyingNetworkRank.Candidate(9, score, "9:wifi:validated");
        assertEquals("9:wifi:validated", UnderlyingNetworkRank.select(Arrays.asList(low, high)));
        assertEquals("9:wifi:validated", UnderlyingNetworkRank.select(Arrays.asList(high, low)));
    }

    private static UnderlyingNetworkRank.Candidate candidate(final long handle, final int transport, final boolean validated,
                                                              final boolean notMetered, final boolean suspended, final String signature) {
        return new UnderlyingNetworkRank.Candidate(handle,
                UnderlyingNetworkRank.score(transport, validated, notMetered, suspended), signature);
    }
}
