package no.uio.keycloak.psso.kerberos;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KerberosRealmConfigTest {

    @Test
    void parsesHostsWithAndWithoutPorts() {
        List<KerberosRealmConfig.KdcAddress> kdcs =
                KerberosRealmConfig.parseKdcHosts(" dc1.example.com , dc2.example.com:8888 ");

        assertEquals(2, kdcs.size());
        assertEquals(new KerberosRealmConfig.KdcAddress("dc1.example.com", 88), kdcs.get(0));
        assertEquals(new KerberosRealmConfig.KdcAddress("dc2.example.com", 8888), kdcs.get(1));
    }

    @Test
    void treatsBareIpv6LiteralAsAHostNotAHostPortPair() {
        List<KerberosRealmConfig.KdcAddress> kdcs =
                KerberosRealmConfig.parseKdcHosts("2001:db8::1");

        assertEquals(1, kdcs.size());
        assertEquals(new KerberosRealmConfig.KdcAddress("2001:db8::1", 88), kdcs.get(0));
    }

    @Test
    void parsesBracketedIpv6WithAndWithoutPort() {
        assertEquals(new KerberosRealmConfig.KdcAddress("::1", 88),
                KerberosRealmConfig.parseKdcHosts("[::1]").get(0));
        assertEquals(new KerberosRealmConfig.KdcAddress("::1", 8888),
                KerberosRealmConfig.parseKdcHosts("[::1]:8888").get(0));
    }

    @Test
    void fallsBackToTheDefaultPortWhenItIsNotUsable() {
        assertEquals(new KerberosRealmConfig.KdcAddress("dc1", 88),
                KerberosRealmConfig.parseKdcHosts("dc1:not-a-port").get(0));
        assertEquals(new KerberosRealmConfig.KdcAddress("dc1", 88),
                KerberosRealmConfig.parseKdcHosts("dc1:99999").get(0));
    }

    @Test
    void skipsBlankAndMalformedEntries() {
        assertTrue(KerberosRealmConfig.parseKdcHosts("  ,  ").isEmpty());
        assertTrue(KerberosRealmConfig.parseKdcHosts(null).isEmpty());
        assertTrue(KerberosRealmConfig.parseKdcHosts("[::1").isEmpty());
    }
}
