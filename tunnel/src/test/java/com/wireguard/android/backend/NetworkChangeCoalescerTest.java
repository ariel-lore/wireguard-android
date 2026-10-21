/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class NetworkChangeCoalescerTest {
    @Test
    public void baseline_does_not_send() {
        final NetworkChangeCoalescer coalescer = new NetworkChangeCoalescer();
        coalescer.baseline("10:wifi:validated");
        assertFalse(coalescer.observe("10:wifi:validated"));
        assertEquals("", coalescer.consume());
    }

    @Test
    public void one_change_is_one_consume() {
        final NetworkChangeCoalescer coalescer = new NetworkChangeCoalescer();
        coalescer.baseline("10:wifi:validated");
        assertTrue(coalescer.observe("20:cellular:validated"));
        assertFalse(coalescer.observe("20:cellular:validated"));
        assertEquals("20:cellular:validated", coalescer.consume());
        assertEquals("", coalescer.consume());
    }

    @Test
    public void rapid_changes_collapse_to_the_last_signature() {
        final NetworkChangeCoalescer coalescer = new NetworkChangeCoalescer();
        coalescer.baseline("10:wifi:validated");
        assertTrue(coalescer.observe("20:cellular:validated"));
        assertTrue(coalescer.observe("30:wifi:validated"));
        assertEquals("30:wifi:validated", coalescer.consume());
        assertFalse(coalescer.observe("30:wifi:validated"));
    }

    @Test
    public void reverting_inside_the_burst_sends_nothing() {
        final NetworkChangeCoalescer coalescer = new NetworkChangeCoalescer();
        coalescer.baseline("10:wifi:validated");
        assertTrue(coalescer.observe("20:cellular:validated"));
        assertTrue(coalescer.observe("10:wifi:validated"));
        assertEquals("", coalescer.consume());
    }

    @Test
    public void keepalive_is_one_shot_and_only_when_enabled_on_a_real_network() {
        assertFalse(NetworkChangeCoalescer.shouldSendKeepalive(false, "20:cellular:validated"));
        assertFalse(NetworkChangeCoalescer.shouldSendKeepalive(true, ""));
        assertFalse(NetworkChangeCoalescer.shouldSendKeepalive(true, NetworkChangeCoalescer.NO_NETWORK));
        assertTrue(NetworkChangeCoalescer.shouldSendKeepalive(true, "20:cellular:validated"));
    }
}
