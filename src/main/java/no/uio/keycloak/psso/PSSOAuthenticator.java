package no.uio.keycloak.psso;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import no.uio.keycloak.psso.token.RefreshTokenValidator;
import org.jboss.logging.Logger;
import org.keycloak.authentication.*;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.RefreshToken;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

public class PSSOAuthenticator  implements Authenticator {
    private static final Logger logger = Logger.getLogger(PSSOAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        HttpHeaders headers = context.getHttpRequest().getHttpHeaders();
        String pSssoHeader = headers.getHeaderString("Platform-SSO-Authorization");
        String ip_address = "";
        String userAgent = "";
        try {
            ip_address = context.getSession().getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
            userAgent = context.getSession().getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
        } catch (Exception e){
            logger.error("Platform SSO: Error getting ip address from user");
        }
        String requestData = "IP Address: " + ip_address+ "User Agent: " + userAgent;

        if (pSssoHeader != null) {
            pSssoHeader = pSssoHeader.replaceFirst("^[Bb]earer\\s+", "");
            String ssoIdB64;
            String sigB64;
            try {
               String[] split = pSssoHeader.split("\\.");
               ssoIdB64 = split[0];
               sigB64 = split[1];
            }catch (Exception e){
                logger.error("Platform SSO: Wrong SSO header format. "+requestData);
                logger.error(e);
                context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
                return;

            }

            byte[] tokenBytes = base64UrlDecode(ssoIdB64);
            byte[] signatureBytes = base64UrlDecode(sigB64);
            ObjectMapper mapper = new ObjectMapper();
            JsonNode env;
            try {
                env = mapper.readTree(tokenBytes);
            } catch (Exception e) {

                logger.error("Platform SSO: Error parsing SSO Token. " + e.getMessage());
                logger.error("Platform SSO: Authentication attempt failed. "+requestData);

                context.attempted();
                return;
            }
            RealmModel realm = context.getRealm();
           if (verifySignature(context, env, ssoIdB64, sigB64, signatureBytes)){
               String refreshToken = env.get("refresh_token").asText();

              // String username = env.get("username").asText();

               String kid = env.get("kid").asText();
               RefreshTokenValidator validator = new RefreshTokenValidator(context.getSession());
               RefreshToken token = validator.validate(refreshToken,"psso");
               String username = token.getSubject();
               if (token != null) {
                   logger.info("Platform SSO: User " + username + " successfully authenticated with SSO Token. "+requestData);
                   UserModel user = context.getSession().users().getUserByUsername(realm,username);
                   context.setUser(user);

                   if (env.has("sid") && !env.get("sid").asText().isEmpty()){
                       String sid = env.get("sid").asText();
                       UserSessionModel existing = context.getSession().sessions().getUserSession(context.getRealm(), sid);
                       if (existing != null) {
                           // Force Keycloak to use this already-active session
                           context.attachUserSession(existing);
                           ;
                       }

                   }

                    logger.info("Platform SSO: User " + username + " successfully authenticated with SSO Token. "+requestData);

                   context.success();
                   return;
               }


                   ;

           }

            context.attempted();

        }else {
            context.attempted();

        }

    }

    private boolean verifySignature(AuthenticationFlowContext context, JsonNode env, String ssoIdB64,  String sigB64,byte[]  signatureBytes) {
        String ip_address = "";
        String userAgent = "";
        try {
            ip_address = context.getSession().getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
            userAgent = context.getSession().getContext().getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
        } catch (Exception e){
            logger.error("Platform SSO: Error getting ip address from user");
        }
        String requestData = "IP Address: " + ip_address+ "User Agent: " + userAgent;


        String username = env.get("username").asText();
        String kid = env.get("kid").asText();
        long signedAt = env.get("signed_at").asLong();

        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - signedAt) > 5) {
            logger.error("Platform SSO: Expired login request. "+requestData);
            context.attempted();
            return false;
        }
        JpaConnectionProvider jpa = context.getSession().getProvider(JpaConnectionProvider.class);
        EntityManager em = jpa.getEntityManager();

        Device device = null;
        try {
            device = em.createNamedQuery("Device.findBySignKeyId", Device.class)
                    .setParameter("signingKeyId", kid)
                    .getSingleResult();
        } catch (Exception e) {
            logger.error("Platform SSO: Error finding device by signingKeyId: " + kid+"- "+ e.getMessage());
            logger.error("Platform SSO: Authentication attempt failed. "+requestData);
            context.attempted();
            return false;
        }
        if (device == null) {
            logger.error("Platform SSO: Error finding device by signingKeyId: " + kid+"- ");
            logger.error("Platform SSO: Authentication attempt failed. "+requestData);
            context.attempted();
            return  false;
        }
          String devicePublicKeyString = device.getSigningKey();
      //  logger.info("Platform SSO: Device public key: " + devicePublicKeyString);
        try {
            byte[] dataToVerify = ssoIdB64.getBytes(StandardCharsets.UTF_8);

            Signature verifier = Signature.getInstance("SHA256withECDSA");
            PublicKey devicePublicKey =  loadPlatformSSOPublicKey(devicePublicKeyString);
            verifier.initVerify(devicePublicKey);
            verifier.update(dataToVerify);
            boolean ok = verifier.verify(signatureBytes);
            logger.info("Platform SSO: Device public key verified: " + ok);
            return ok;
        }catch (Exception e){
            logger.error("Platform SSO: Error verifying SSO Token. " + e.getMessage());
            logger.error("Platform SSO: Authentication attempt failed. "+requestData+ " User: " + username+" Device: " + device.getSerialNumber());
            context.attempted();
            return false;
        }



    }

    public static PublicKey loadPlatformSSOPublicKey(String base64OrPem) throws Exception {
        // Trim whitespace
        if (base64OrPem == null) throw new IllegalArgumentException("null key");
        String key = base64OrPem.trim();

        // If it looks like PEM, strip headers and decode
        if (key.contains("BEGIN PUBLIC KEY")) {
            key = key.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(key);
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        }

        // Otherwise assume it's base64 of either:
        // - raw EC point (0x04 || X || Y, length 65) OR
        // - DER SubjectPublicKeyInfo (starts with 0x30)
        byte[] decoded = Base64.getDecoder().decode(key);

        // If it's X.509 DER already (starts with 0x30), use it directly
        if (decoded.length > 0 && decoded[0] == 0x30) {
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(decoded));
        }

        // If it's the raw uncompressed EC point (0x04 + X + Y) (65 bytes for P-256), wrap it
        if (decoded.length == 65 && decoded[0] == 0x04) {
            byte[] prefix = new byte[] {
                    0x30, 0x59,
                    0x30, 0x13,
                    0x06, 0x07,
                    0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x02, 0x01,
                    0x06, 0x08,
                    0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x03, 0x01, 0x07,
                    0x03, 0x42, 0x00
            };
            byte[] x509 = new byte[prefix.length + decoded.length];
            System.arraycopy(prefix, 0, x509, 0, prefix.length);
            System.arraycopy(decoded, 0, x509, prefix.length, decoded.length);
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(x509));
        }

        // Last resort: throw informative error
        throw new IllegalArgumentException("Unsupported key format: decoded length=" + decoded.length);
    }


    private byte[] base64UrlDecode(String input) {
        String s = input
                .replace('-', '+')
                .replace('_', '/');

        // Pad with '=' if needed
        switch (s.length() % 4) {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }

        return Base64.getDecoder().decode(s);
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return Collections.singletonList((PSSORequiredAction)session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class,
                PSSORequiredAction.PROVIDER_ID));
    }
    @Override
    public void close() {

    }
}
