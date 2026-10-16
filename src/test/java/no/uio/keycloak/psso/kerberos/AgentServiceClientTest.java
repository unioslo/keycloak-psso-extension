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

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives {@link AgentServiceClient} against a stub enrollment-agent HTTPS server that requires
 * mutual TLS, parses the CSR, and issues a certificate — exercising the mTLS wiring, CSR
 * construction, and response parsing end to end without a real AD CS.
 */
class AgentServiceClientTest {

    private static final String REALM = "AD.EXAMPLE.COM";

    private TestCa ca;                 // doubles as mTLS trust root and the issuing "AD CS"
    private HttpsServer server;
    private String url;
    private String clientCertPem;
    private String clientKeyPem;
    private final AtomicReference<PKCS10CertificationRequest> received = new AtomicReference<>();
    private volatile int issuedStatus = 200;

    @BeforeEach
    void startServer() throws Exception {
        ca = new TestCa("CN=Agent Test CA,O=" + REALM);

        KeyPair serverKeys = rsa();
        X509Certificate serverCert = ca.issue("CN=localhost", serverKeys.getPublic(),
                new GeneralName(GeneralName.dNSName, "localhost"));

        KeyPair clientKeys = rsa();
        X509Certificate clientCert = ca.issue("CN=keycloak", clientKeys.getPublic());
        clientCertPem = TestCa.pem("CERTIFICATE", clientCert.getEncoded());
        clientKeyPem = TestCa.pem("PRIVATE KEY", clientKeys.getPrivate().getEncoded());

        SSLContext serverCtx = serverContext(serverCert, serverKeys, ca.certificate);
        server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverCtx) {
            @Override
            public void configure(HttpsParameters params) {
                params.setNeedClientAuth(true);   // demand Keycloak's client certificate
            }
        });
        server.createContext("/issue", exchange -> {
            try {
                byte[] reqBytes = exchange.getRequestBody().readAllBytes();
                JSONObject req = new JSONObject(new String(reqBytes, StandardCharsets.UTF_8));
                byte[] csr = Base64.getDecoder().decode(req.getString("csr"));
                received.set(new PKCS10CertificationRequest(csr));

                if (issuedStatus != 200) {
                    byte[] err = new JSONObject().put("error", "template denied").toString()
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(issuedStatus, err.length);
                    exchange.getResponseBody().write(err);
                    exchange.close();
                    return;
                }

                // Issue a cert for the CSR's public key, as AD CS would on the user's behalf.
                PublicKey csrKey = new JcaPKCS10CertificationRequest(received.get()).getPublicKey();
                X509Certificate issued = ca.issue("CN=" + req.getString("username"), csrKey);
                byte[] body = new JSONObject()
                        .put("certificate", Base64.getEncoder().encodeToString(issued.getEncoded()))
                        .toString().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            } catch (Exception e) {
                throw new java.io.IOException(e);
            }
        });
        server.start();
        url = "https://localhost:" + server.getAddress().getPort() + "/issue";
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void issuesACertificateOverMutualTlsAndKeepsTheKeyLocal() throws Exception {
        CertificateSource.IssuedIdentity identity = client().issueFor("alice", REALM);

        // The returned certificate's public key must pair with the private key we hold locally.
        RSAPublicKey certKey = (RSAPublicKey) identity.certificate().getPublicKey();
        RSAPrivateKey privKey = (RSAPrivateKey) identity.privateKey();
        assertEquals(certKey.getModulus(), privKey.getModulus(),
                "returned certificate must match the locally-generated private key");
        assertEquals("CN=alice", identity.certificate().getSubjectX500Principal().getName());
    }

    @Test
    void sendsACsrCarryingTheUpnSanAndNeverThePrivateKey() throws Exception {
        CertificateSource.IssuedIdentity identity = client().issueFor("alice", REALM);

        PKCS10CertificationRequest csr = received.get();
        assertNotNull(csr, "server never received a CSR");

        // The CSR's key is the one that pairs with the identity we got back — i.e. it is a public
        // key, and the only private key lives in the returned identity, never on the wire.
        PublicKey csrKey = new JcaPKCS10CertificationRequest(csr).getPublicKey();
        assertEquals(((RSAPublicKey) identity.certificate().getPublicKey()).getModulus(),
                ((RSAPublicKey) csrKey).getModulus());

        assertEquals("alice@" + REALM, upnFromCsr(csr));
    }

    @Test
    void surfacesTheAgentsErrorBody() throws Exception {
        issuedStatus = 403;
        AgentServiceClient client = client();

        Exception e = org.junit.jupiter.api.Assertions.assertThrows(Exception.class,
                () -> client.issueFor("alice", REALM));
        assertTrue(e.getMessage().contains("403") && e.getMessage().contains("template denied"),
                "expected the agent's error detail, got: " + e.getMessage());
    }

    private AgentServiceClient client() throws Exception {
        return new AgentServiceClient(new KerberosRealmConfig.Builder()
                .realm(REALM)
                .certSource(CertSource.AGENT_SERVICE)
                .agentServiceUrl(url)
                .agentClientCertPem(clientCertPem)
                .agentClientKeyPem(clientKeyPem)
                .agentServerCaPem(ca.certificatePem())
                .build());
    }

    private static String upnFromCsr(PKCS10CertificationRequest csr) throws Exception {
        var attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        Extensions extensions = Extensions.getInstance(attrs[0].getAttrValues().getObjectAt(0));
        GeneralNames sans = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        for (GeneralName name : sans.getNames()) {
            if (name.getTagNo() == GeneralName.otherName) {
                ASN1Sequence otherName = ASN1Sequence.getInstance(name.getName());
                if ("1.3.6.1.4.1.311.20.2.3".equals(
                        ASN1ObjectIdentifier.getInstance(otherName.getObjectAt(0)).getId())) {
                    return DERUTF8String.getInstance(
                            ASN1TaggedObject.getInstance(otherName.getObjectAt(1)).getBaseObject())
                            .getString();
                }
            }
        }
        throw new AssertionError("no UPN SAN in CSR");
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static SSLContext serverContext(X509Certificate cert, KeyPair keys, X509Certificate trust)
            throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("server", keys.getPrivate(), new char[0], new X509Certificate[]{cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("ca", trust);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }
}
