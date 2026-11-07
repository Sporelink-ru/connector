package ru.sporelink.connector;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;

public class NodeKey {
    private final Ed25519PrivateKeyParameters priv;
    private final Ed25519PublicKeyParameters pub;

    private NodeKey(Ed25519PrivateKeyParameters priv, Ed25519PublicKeyParameters pub) {
        this.priv = priv;
        this.pub = pub;
    }

    public static NodeKey loadOrCreate(String path) throws Exception {
        Path p = Path.of(path);
        if (Files.exists(p)) {
            byte[] raw = Base64.getDecoder().decode(Files.readString(p).trim());
            Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(raw, 0);
            return new NodeKey(priv, priv.generatePublicKey());
        }
        
        // Создаем родительскую директорию, если её нет!
        if (p.getParent() != null) {
            Files.createDirectories(p.getParent());
        }

        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        NodeKey k = new NodeKey(
                (Ed25519PrivateKeyParameters) kp.getPrivate(),
                (Ed25519PublicKeyParameters) kp.getPublic());
        Files.writeString(p, Base64.getEncoder().encodeToString(k.priv.getEncoded()));
        System.out.println("✓ Generated node key at " + p);
        return k;
    }
    
    public Ed25519PrivateKeyParameters privateKey() { return priv; }
    public Ed25519PublicKeyParameters publicKey()   { return pub; }
    public String publicKeyBase64() {
        return Base64.getEncoder().encodeToString(pub.getEncoded());
    }
}