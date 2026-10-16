/* Copyright 2026 University of Oslo, Norway
 # This file is part of the Keycloak Platform SSO Extension codebase.
 #
 # This extension for Keycloak is free software; you can redistribute
 # it and/or modify it under the terms of the GNU General Public License
 # as published by the Free Software Foundation;
 # either version 2 of the License, or (at your option) any later version.
 #
 # This extension is distributed in the hope that it will be useful, but
 # WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this extension; if not, write to the Free Software Foundation,
 # Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
*/
package no.uio.keycloak.psso.kerberos;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The MDM-driven opt-in: a ticket is only fetched when the Mac asks for one, either via a custom
 * login-request claim or an extra scope.
 */
class KerberosTriggerTest {

    private static final String TRIGGER = "fetch_kerberos_tgt";

    @Test
    void withoutATriggerConfiguredEveryLoginQualifies() throws Exception {
        assertTrue(requested("", Map.of()));
        assertTrue(requested("", Map.of("scope", "openid urn:apple:platformsso")));
    }

    @Test
    void acceptsTheTriggerAsABodyClaim() throws Exception {
        assertTrue(requested(TRIGGER, Map.of(TRIGGER, true)));
        assertTrue(requested(TRIGGER, Map.of(TRIGGER, "true")));
        assertTrue(requested(TRIGGER, Map.of(TRIGGER, "yes")));
    }

    @Test
    void acceptsTheTriggerAsAScopeValue() throws Exception {
        assertTrue(requested(TRIGGER, Map.of("scope", "openid " + TRIGGER + " urn:apple:platformsso")));
    }

    @Test
    void rejectsWhenAbsentOrExplicitlyOff() throws Exception {
        assertFalse(requested(TRIGGER, Map.of()));
        assertFalse(requested(TRIGGER, Map.of(TRIGGER, false)));
        assertFalse(requested(TRIGGER, Map.of(TRIGGER, "false")));
        assertFalse(requested(TRIGGER, Map.of(TRIGGER, "0")));
        assertFalse(requested(TRIGGER, Map.of("scope", "openid urn:apple:platformsso")));
    }

    @Test
    void doesNotMatchAScopeThatMerelyContainsTheTrigger() throws Exception {
        assertFalse(requested(TRIGGER, Map.of("scope", "openid " + TRIGGER + "_extra")));
        assertFalse(requested(TRIGGER, Map.of("scope", "openid not_" + TRIGGER)));
    }

    /** Exercises the private gate directly; building a full service needs a Keycloak realm. */
    private static boolean requested(String trigger, Map<String, Object> claims) throws Exception {
        KerberosRealmConfig config = config(trigger);
        Object service = serviceWith(config);
        Method requested = KerberosTgtService.class.getDeclaredMethod("requested", Map.class);
        requested.setAccessible(true);
        return (boolean) requested.invoke(service, new HashMap<>(claims));
    }

    private static KerberosRealmConfig config(String trigger) {
        return new KerberosRealmConfig.Builder()
                .realm("EXAMPLE.COM")
                .kdcs(java.util.List.of(new KerberosRealmConfig.KdcAddress("kdc", 88)))
                .triggerClaim(trigger)
                .build();
    }

    private static Object serviceWith(KerberosRealmConfig config) throws Exception {
        var ctor = KerberosTgtService.class.getDeclaredConstructor(KerberosRealmConfig.class);
        ctor.setAccessible(true);
        return ctor.newInstance(config);
    }
}
