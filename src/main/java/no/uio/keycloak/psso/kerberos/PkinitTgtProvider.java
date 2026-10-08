package no.uio.keycloak.psso.kerberos;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.jboss.logging.Logger;

import java.io.IOException;

/**
 * Obtains a TGT via PKINIT with a short-lived certificate from a {@link CertificateSource}.
 *
 * This is the credential-less path: Secure Enclave, refresh and token-exchange grants carry no
 * password, so the Keycloak session itself is the proof of identity and the certificate turns
 * that proof into something a KDC accepts.
 */
public final class PkinitTgtProvider implements KerberosTgtProvider {

    private static final Logger logger = Logger.getLogger(PkinitTgtProvider.class);

    private final KerberosRealmConfig config;
    private final CertificateSource certificateSource;

    public PkinitTgtProvider(KerberosRealmConfig config, CertificateSource certificateSource) {
        this.config = config;
        this.certificateSource = certificateSource;
    }

    @Override
    public String name() {
        return "pkinit/" + certificateSource.name();
    }

    @Override
    public KerberosTgt obtain(KerberosTgtRequest request) throws Exception {
        String clientName = clientName(request.principal());

        CertificateSource.IssuedIdentity identity =
                certificateSource.issueFor(clientName, config.realm());

        IOException lastUnreachable = null;
        for (KerberosRealmConfig.KdcAddress kdc : config.kdcs()) {
            try {
                logger.debugf("Platform SSO: Requesting TGT for %s from %s:%d via PKINIT (%s).",
                        request.principal(), kdc.host(), kdc.port(), certificateSource.name());

                TgtTicket tgt = new PkinitExchange(config).requestTgt(clientName, identity, kdc);
                return AsRepPackager.pack(tgt, config.asRepKeyMode());

            } catch (IOException e) {
                // Transport only; protocol and certificate errors repeat on every KDC and
                // propagate immediately.
                logger.warnf("Platform SSO: KDC %s:%d unreachable (%s); trying next.",
                        kdc.host(), kdc.port(), e.getMessage());
                lastUnreachable = e;
            }
        }

        if (lastUnreachable != null) {
            throw lastUnreachable;
        }
        throw new KrbException("No KDC configured for realm " + config.realm());
    }

    /** PkinitExchange applies the configured realm itself, so strip any "@REALM" suffix. */
    private static String clientName(String principal) {
        int at = principal.lastIndexOf('@');
        return at > 0 ? principal.substring(0, at) : principal;
    }
}
