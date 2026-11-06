package ru.sporelink.connector;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class Signer {

    /** Canonical message for 2PC request signing. */
    private static String canonical(String method, String path, long ts, byte[] body) {
        String bodyHash = sha256Hex(body);
        return "SPORELINK-TX-V1\n" + method + "\n" + path + "\n" + ts + "\n" + bodyHash;
    }

    public static String sign(NodeKey key, String method, String path, long ts, byte[] body) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, key.privateKey());
        byte[] msg = canonical(method, path, ts, body).getBytes(StandardCharsets.UTF_8);
        signer.update(msg, 0, msg.length);
        return Base64.getEncoder().encodeToString(signer.generateSignature());
    }

    public static boolean verify(Ed25519PublicKeyParameters pub,
                                 String method, String path, long ts,
                                 byte[] body, String sigB64) {
        try {
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, pub);
            byte[] msg = canonical(method, path, ts, body).getBytes(StandardCharsets.UTF_8);
            verifier.update(msg, 0, msg.length);
            return verifier.verifySignature(Base64.getDecoder().decode(sigB64));
        } catch (Exception e) {
            return false;
        }
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}