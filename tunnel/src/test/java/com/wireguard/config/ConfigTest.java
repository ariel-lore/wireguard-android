/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ConfigTest {

    @Test(expected = BadConfigException.class)
    public void invalid_config_throws() throws IOException, BadConfigException {
        try (final InputStream is = Objects.requireNonNull(getClass().getClassLoader()).getResourceAsStream("broken.conf")) {
            Config.parse(is);
        }
    }

    @Test
    public void valid_config_parses_correctly() throws IOException, ParseException {
        Config config = null;
        final Collection<InetNetwork> expectedAllowedIps = new HashSet<>(Arrays.asList(InetNetwork.parse("0.0.0.0/0"), InetNetwork.parse("::0/0")));
        try (final InputStream is = Objects.requireNonNull(getClass().getClassLoader()).getResourceAsStream("working.conf")) {
            config = Config.parse(is);
        } catch (final BadConfigException e) {
            fail("'working.conf' should never fail to parse");
        }
        assertNotNull("config cannot be null after parsing", config);
        assertTrue(
                "No applications should be excluded by default",
                config.getInterface().getExcludedApplications().isEmpty()
        );
        assertEquals("Test config has exactly one peer", 1, config.getPeers().size());
        assertEquals("Test config's allowed IPs are 0.0.0.0/0 and ::0/0", config.getPeers().get(0).getAllowedIps(), expectedAllowedIps);
        assertEquals("Test config has one DNS server", 1, config.getInterface().getDnsServers().size());
        assertTrue("Missing comment defaults to one keepalive on network change", config.getInterface().isKeepaliveOnNetworkChange());
    }

    @Test
    public void keepalive_comment_round_trips_without_a_wg_quick_key() throws IOException, BadConfigException {
        final String original;
        try (final InputStream is = Objects.requireNonNull(getClass().getClassLoader()).getResourceAsStream("working.conf")) {
            original = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
        final Config enabled = Config.parse(new BufferedReader(new StringReader(original)));
        final String exported = enabled.toWgQuickString();
        assertTrue(exported.contains("\n# KeepaliveOnNetworkChange = true\n"));
        assertFalse(enabled.toWgUserspaceString().contains("KeepaliveOnNetworkChange"));
        for (final String line : exported.split("\n")) {
            final String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#"))
                continue;
            assertFalse(trimmed.toLowerCase(Locale.ROOT).startsWith("keepaliveonnetworkchange"));
        }

        final String disabledText = exported.replace("# KeepaliveOnNetworkChange = true", "# KeepaliveOnNetworkChange = false");
        final Config disabled = Config.parse(new BufferedReader(new StringReader(disabledText)));
        assertFalse(disabled.getInterface().isKeepaliveOnNetworkChange());
        assertTrue(disabled.toWgQuickString().contains("# KeepaliveOnNetworkChange = false"));
        assertNotEquals(enabled.getInterface(), disabled.getInterface());
        assertEquals(enabled.getPeers(), disabled.getPeers());

        final String spaced = exported.replace("# KeepaliveOnNetworkChange = true", "#   KeepaliveOnNetworkChange = FALSE");
        assertFalse(Config.parse(new BufferedReader(new StringReader(spaced))).getInterface().isKeepaliveOnNetworkChange());

        final String peerOnly = original + "\n# KeepaliveOnNetworkChange = false\n";
        assertTrue("A comment outside [Interface] does not turn the option off",
                Config.parse(new BufferedReader(new StringReader(peerOnly))).getInterface().isKeepaliveOnNetworkChange());
    }
}
