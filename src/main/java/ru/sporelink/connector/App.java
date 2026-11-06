package ru.sporelink.connector;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

public class App 
{
    static String canonicalize(JsonNode node, ObjectMapper mapper) throws Exception {
        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;
            List<String> keys = new ArrayList<>();
            obj.fieldNames().forEachRemaining(keys::add);
            keys.sort(String::compareTo); // UTF-16 code unit ordering, как в JCS

            StringJoiner sj = new StringJoiner(",", "{", "}");
            for (String k : keys) {
                sj.add(mapper.writeValueAsString(k) + ":" + canonicalize(obj.get(k), mapper));
            }
            return sj.toString();
        } else if (node.isArray()) {
            StringJoiner sj = new StringJoiner(",", "[", "]");
            for (JsonNode el : node) {
                sj.add(canonicalize(el, mapper));
            }
            return sj.toString();
        } else {
            return mapper.writeValueAsString(node);
        }
    }

    public static void main(String[] args) throws Exception {
        var baseUrl = args[0];
        var client = HttpClient.newHttpClient();
        var mapper = new ObjectMapper();

        // 1. Получаем well-known
        var wk = get(client, baseUrl + "/.well-known/mc-federation");
        var wkJson = mapper.readTree(wk);
        var pubKeyB64 = wkJson.at("/public_keys/server_signing_key").asText()
                              .replace("ed25519:", "");
        System.out.println("✓ Well-known: " + wkJson.get("server_name").asText());

        // 2. Получаем манифест
        var mfJson = mapper.readTree(get(client, baseUrl + "/federation/manifest"));
        var signatures = mfJson.get("signatures");
        var sigNode = signatures.get(0);
        var sigB64 = sigNode.get("sig").asText();
        var signer = sigNode.get("signer").asText();

        // 3. Канонизация и проверка
        var toSign = (ObjectNode) mfJson.deepCopy();
        toSign.remove("signatures");
        String canonical = canonicalize(toSign, mapper);
        var signingInput = "SPORELINK-MANIFEST-V1\n" + canonical;

        byte[] signingBytes = signingInput.getBytes(StandardCharsets.UTF_8);
        Ed25519PublicKeyParameters pub = new Ed25519PublicKeyParameters(
            Base64.getDecoder().decode(pubKeyB64), 0);
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, pub);
        verifier.update(signingBytes, 0, signingBytes.length);
        boolean ok = verifier.verifySignature(Base64.getDecoder().decode(sigB64));

        System.out.println((ok ? "✓" : "✗") + " Подпись манифеста от " + signer);
        if (!ok) System.exit(1);
    }

    static String get(HttpClient c, String url) throws Exception {
        return c.send(HttpRequest.newBuilder(URI.create(url)).build(),
                      HttpResponse.BodyHandlers.ofString()).body();
    }
}
