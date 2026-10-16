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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.jboss.logging.Logger;
import org.json.JSONObject;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.HttpsURLConnection;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Obtains the PKINIT client certificate from an external enrollment-agent service (the Active
 * Directory path), over mutual TLS.
 *
 * Keycloak generates the key pair and a PKCS#10 CSR locally and sends only the CSR — the private
 * key never leaves Keycloak, so a compromise of the agent service or its transport cannot recover
 * it. The agent co-signs the request with its enrollment-agent certificate, has AD CS issue a
 * logon certificate on the user's behalf, and returns just the certificate. The exchange contract
 * is deliberately certificate-authority-agnostic (CSR in, certificate out); whether the agent
 * reaches AD CS by DCOM or CES is its own concern.
 *
 * Contract (JSON over HTTPS POST to the configured URL):
 * <pre>
 *   request  { "username": "...", "realm": "...", "csr": "&lt;base64 PKCS#10 DER&gt;" }
 *   response { "certificate": "&lt;base64 DER or PEM&gt;" }   (HTTP 200)
 *            { "error": "..." }                          (non-2xx)
 * </pre>
 */
public final class AgentServiceClient implements CertificateSource {

    private static final Logger logger = Logger.getLogger(AgentServiceClient.class);

    private static final String ID_MS_UPN_SAN = "1.3.6.1.4.1.311.20.2.3";
    private static final int CONNECT_TIMEOUT_MS = 5000;

    private final String serviceUrl;
    private final SSLSocketFactory sslSocketFactory;
    private final int readTimeoutMs;

    public AgentServiceClient(KerberosRealmConfig config) throws Exception {
        this.serviceUrl = config.agentServiceUrl();
        this.readTimeoutMs = config.timeoutMs();
        this.sslSocketFactory = buildMutualTlsContext(
                config.agentClientCertPem(), config.agentClientKeyPem(), config.agentServerCaPem())
                .getSocketFactory();
    }

    @Override
    public String name() {
        return "agent-service";
    }

    @Override
    public IssuedIdentity issueFor(String clientName, String realm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        byte[] csrDer = buildCsr(clientName, realm, keyPair);

        JSONObject request = new JSONObject();
        request.put("username", clientName);
        request.put("realm", realm);
        request.put("csr", Base64.getEncoder().encodeToString(csrDer));

        X509Certificate certificate = post(request);
        logger.debugf("Platform SSO: Enrollment agent issued a certificate for %s@%s (subject %s).",
                clientName, realm, certificate.getSubjectX500Principal().getName());

        return new IssuedIdentity(certificate, keyPair.getPrivate());
    }

    /**
     * A PKCS#10 carrying the public key, a CN, and the Microsoft UPN SAN. The agent and its AD CS
     * template decide the authoritative identity (enroll-on-behalf-of), but supplying the UPN
     * covers templates configured to take the subject from the request.
     */
    byte[] buildCsr(String clientName, String realm, KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=" + clientName);

        ExtensionsGenerator extensions = new ExtensionsGenerator();
        GeneralName upn = new GeneralName(GeneralName.otherName, new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{
                new ASN1ObjectIdentifier(ID_MS_UPN_SAN),
                new DERTaggedObject(true, 0, new DERUTF8String(clientName + "@" + realm))
        }));
        extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(upn));

        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return builder.build(signer).getEncoded();
    }

    private X509Certificate post(JSONObject request) throws Exception {
        URI uri = URI.create(serviceUrl);
        HttpURLConnection raw = (HttpURLConnection) uri.toURL().openConnection();
        if (!(raw instanceof HttpsURLConnection connection)) {
            throw new IllegalStateException("Enrollment agent URL must be https: " + serviceUrl);
        }
        connection.setSSLSocketFactory(sslSocketFactory);
        connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
        connection.setReadTimeout(readTimeoutMs);
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Accept", "application/json");

        try (OutputStream out = connection.getOutputStream()) {
            out.write(request.toString().getBytes(StandardCharsets.US_ASCII));
        }

        int status = connection.getResponseCode();
        String body = readBody(status < 400
                ? connection.getInputStream() : connection.getErrorStream());

        if (status < 200 || status >= 300) {
            String detail = body.isEmpty() ? "" : ": " + extractError(body);
            throw new java.io.IOException("Enrollment agent returned HTTP " + status + detail);
        }

        String certB64 = new JSONObject(body).getString("certificate");
        return parseCertificate(certB64);
    }

    private static String extractError(String body) {
        try {
            return new JSONObject(body).optString("error", body);
        } catch (Exception e) {
            // Not JSON, or no "error" field — the raw body is the best detail we have.
            return body;
        }
    }

    /** Accepts either base64-DER or a PEM block in the "certificate" field. */
    static X509Certificate parseCertificate(String value) throws Exception {
        String trimmed = value.trim();
        byte[] der = trimmed.contains("-----BEGIN")
                ? trimmed.getBytes(StandardCharsets.US_ASCII)
                : Base64.getMimeDecoder().decode(trimmed);
        try (InputStream in = new ByteArrayInputStream(der)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    /**
     * mTLS: present Keycloak's client certificate, and trust the agent's server certificate via
     * the configured CA. An empty server CA falls back to the JVM default trust store.
     */
    static SSLContext buildMutualTlsContext(String clientCertPem, String clientKeyPem,
                                            String serverCaPem) throws Exception {
        X509Certificate clientCert = LocalCaIssuer.parseCertificate(clientCertPem);
        PrivateKey clientKey = LocalCaIssuer.parsePrivateKey(clientKeyPem);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("client", clientKey, new char[0], new X509Certificate[]{clientCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);

        TrustManagerFactory tmf = null;
        if (serverCaPem != null && !serverCaPem.isBlank()) {
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);
            int i = 0;
            for (X509Certificate ca : PkinitExchange.parseAnchors(serverCaPem)) {
                trustStore.setCertificateEntry("ca" + i++, ca);
            }
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
        }

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf == null ? null : tmf.getTrustManagers(), null);
        return context;
    }

    private static String readBody(InputStream in) throws Exception {
        if (in == null) {
            return "";
        }
        try (in) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
