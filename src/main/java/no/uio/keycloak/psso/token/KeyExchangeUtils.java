package no.uio.keycloak.psso.token;

import com.nimbusds.jose.Payload;
import no.uio.keycloak.psso.Device;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.ECPoint;

import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jboss.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class KeyExchangeUtils {
    static Logger logger = Logger.getLogger(KeyExchangeUtils.class);
    public static Payload keyRequestResponse(Device device, String username){
        // generate the certificate
        KeyPairGenerator kpg = null;
        try {
           kpg = KeyPairGenerator.getInstance("EC");
           kpg.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPair kp = kpg.generateKeyPair();

        PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = kp.getPublic();
        X500Name subject = new X500Name("CN=" + username);

        Instant now = Instant.now();

        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plusSeconds(86400));

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        ContentSigner signer =
                new JcaContentSignerBuilder("SHA256withECDSA")
                        .build(privateKey);

        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(
                        subject,
                        serial,
                        notBefore,
                        notAfter,
                        subject,
                        publicKey
                );

        X509CertificateHolder holder = builder.build(signer);

        X509Certificate cert =
                new JcaX509CertificateConverter().getCertificate(holder);
        String certificate = Base64.getUrlEncoder().withoutPadding()
                           .encodeToString(cert.getEncoded());
        byte[] symmetricKey =
                    Base64.getDecoder().decode(device.getKeyExchangeKey());
        byte[] privateKeyBytes = privateKey.getEncoded();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey, "AES");
        byte[] nonce = new byte[12];
        SecureRandom random = new SecureRandom();
            random.nextBytes(nonce);
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
        byte[] ciphertext = cipher.doFinal(privateKeyBytes);
        ByteBuffer buffer = ByteBuffer.allocate(nonce.length + ciphertext.length);
        buffer.put(nonce);
        buffer.put(ciphertext);

        byte[] encryptedKey = buffer.array();
        String keyContext =
                    Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(encryptedKey);


        Map<String, Object> payload = new HashMap<>();
        payload.put("certificate", certificate);
        payload.put("key_context", keyContext);
        payload.put("iat", now.getEpochSecond());
        payload.put("exp", now.plusSeconds(300).getEpochSecond());
        return new Payload(payload);

        } catch (Exception e) {
            logger.error("Platform SSO: failed to generate certificate", e);
            return null;
        }


    }

    public static Payload keyExchangeResponse(Device device,
                                              String otherPublicKey,
                                              String keyContext) {

        try {
            byte[] symmetricKey =
                    Base64.getDecoder().decode(device.getKeyExchangeKey());

            byte[] encryptedKey =
                    Base64.getUrlDecoder().decode(keyContext);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            SecretKeySpec keySpec = new SecretKeySpec(symmetricKey, "AES");

            byte[] nonce = new byte[12];
            byte[] ciphertext = new byte[encryptedKey.length - 12];

            System.arraycopy(encryptedKey, 0, nonce, 0, 12);
            System.arraycopy(encryptedKey, 12, ciphertext, 0, ciphertext.length);

            GCMParameterSpec spec = new GCMParameterSpec(128, nonce);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);

            byte[] privateKeyBytes = cipher.doFinal(ciphertext);

            KeyFactory keyFactory = KeyFactory.getInstance("EC");

            PKCS8EncodedKeySpec pkcs8 =
                    new PKCS8EncodedKeySpec(privateKeyBytes);

            PrivateKey privateKey =
                    keyFactory.generatePrivate(pkcs8);

            byte[] devicePubBytes =
                    Base64.getDecoder().decode(otherPublicKey);

            KeyFactory kf = KeyFactory.getInstance("EC");

            ECParameterSpec ecSpec =
                    ((ECPrivateKey) privateKey).getParams();

            ECPoint point =
                    ECPointUtil.decodePoint(ecSpec.getCurve(), devicePubBytes);

            ECPublicKeySpec pubSpec =
                    new ECPublicKeySpec(point, ecSpec);

            PublicKey devicePublicKey =
                    kf.generatePublic(pubSpec);

            KeyAgreement ka =
                    KeyAgreement.getInstance("ECDH");

            ka.init(privateKey);
            ka.doPhase(devicePublicKey, true);

            byte[] sharedSecret = ka.generateSecret();

            String key =
                    Base64.getEncoder().encodeToString(sharedSecret);

            Instant now = Instant.now();

            Map<String, Object> payload = new HashMap<>();

            payload.put("key", key);
            payload.put("key_context", keyContext);
            payload.put("iat", now.getEpochSecond());
            payload.put("exp", now.plusSeconds(300).getEpochSecond());

            return new Payload(payload);

        } catch (Exception e) {
            logger.error("Platform SSO: key_exchange failed", e);
            return null;
        }
    }
}
