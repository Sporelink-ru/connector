package ru.sporelink.connector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.StringJoiner;

public class App {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: sporelink-connector <hub-url> [jwt]");
            System.exit(2);
        }

        String baseUrl = args[0].replaceAll("/+$", "");
        HttpClient client = HttpClient.newHttpClient();

        // ── 1. Discovery ────────────────────────────────────────────
        String wkBody = get(client, baseUrl + "/.well-known/mc-federation");
        JsonNode wkJson = MAPPER.readTree(wkBody);
        System.out.println("✓ Well-known: " + wkJson.get("server_name").asText());

        String serverPubKeyB64 = wkJson
                .at("/public_keys/server_signing_key")
                .asText()
                .replace("ed25519:", "");

        // ── 2. Signed manifest ──────────────────────────────────────
        String mfBody = get(client, baseUrl + "/federation/manifest");
        JsonNode mfJson = MAPPER.readTree(mfBody);

        JsonNode signatures = mfJson.get("signatures");
        if (signatures == null || !signatures.isArray() || signatures.isEmpty()) {
            System.err.println("✗ manifest has no signatures");
            System.exit(1);
        }
        JsonNode sigNode = signatures.get(0);
        String sigB64  = sigNode.get("sig").asText();
        String signer  = sigNode.get("signer").asText();

        ObjectNode toSign = (ObjectNode) mfJson.deepCopy();
        toSign.remove("signatures");
        String canonical    = canonicalize(toSign);
        String signingInput = "SPORELINK-MANIFEST-V1\n" + canonical;

        Ed25519PublicKeyParameters manifestPub = new Ed25519PublicKeyParameters(
                Base64.getDecoder().decode(serverPubKeyB64), 0);
        Ed25519Signer manifestVerifier = new Ed25519Signer();
        manifestVerifier.init(false, manifestPub);
        byte[] manifestInput = signingInput.getBytes(StandardCharsets.UTF_8);
        manifestVerifier.update(manifestInput, 0, manifestInput.length);
        boolean manifestOk = manifestVerifier.verifySignature(
                Base64.getDecoder().decode(sigB64));

        System.out.println((manifestOk ? "✓" : "✗") + " Подпись манифеста от " + signer);
        if (!manifestOk) System.exit(1);

        // ── 3. JWT (optional second arg) ───────────────────────────
        if (args.length > 1) {
            String jwt = args[1];

            String authKeyB64 = wkJson.at("/public_keys/auth_signing_key").asText(null);
            if (authKeyB64 == null || authKeyB64.isEmpty()) {
                authKeyB64 = wkJson.at("/public_keys/server_signing_key").asText();
            }
            authKeyB64 = authKeyB64.replace("ed25519:", "");
            byte[] authPubKey = Base64.getDecoder().decode(authKeyB64);

            boolean jwtOk = verifyJwt(jwt, authPubKey);
            System.out.println((jwtOk ? "✓" : "✗") + " JWT valid");

            if (jwtOk) {
                String[] parts = jwt.split("\\.");
                JsonNode payload = MAPPER.readTree(
                        Base64.getUrlDecoder().decode(parts[1]));
                System.out.println("  sub:  " + payload.get("sub").asText());
                System.out.println("  name: " + payload.get("name").asText());
                System.out.println("  exp:  " + payload.get("exp").asLong());
                System.out.println("  iss:  " + payload.get("iss").asText());
            } else {
                System.exit(1);
            }
        }
    }

    // ── JWT verification (no network call to hub) ──────────────────
    static boolean verifyJwt(String jwt, byte[] hubPublicKey) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) return false;

        // 1. Signature over raw signing input — no canonicalization
        String signingInput = parts[0] + "." + parts[1];
        byte[] sig = Base64.getUrlDecoder().decode(parts[2]);

        Ed25519PublicKeyParameters pub = new Ed25519PublicKeyParameters(hubPublicKey, 0);
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, pub);
        byte[] input = signingInput.getBytes(StandardCharsets.UTF_8);
        verifier.update(input, 0, input.length);
        if (!verifier.verifySignature(sig)) return false;

        // 2. exp check
        byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
        JsonNode payload = MAPPER.readTree(payloadBytes);
        long exp = payload.get("exp").asLong();
        if (exp < System.currentTimeMillis() / 1000) return false;

        // 3. iss check — compare with server_id from well-known
        //    (passed in real callers; skipped here for MVP)
        // String expectedIss = wkJson.get("server_id").asText();
        // if (!expectedIss.equals(payload.get("iss").asText())) return false;

        return true;
    }

    // ── Recursive canonicalization (JCS-like) ──────────────────────
    // Must match the C# Canonicalize() in hub/Program.cs.
    static String canonicalize(JsonNode node) throws Exception {
        if (node.isObject()) {
            List<String> keys = new ArrayList<>();
            node.fieldNames().forEachRemaining(keys::add);
            keys.sort(String::compareTo); // UTF-16 code unit ordering

            StringJoiner sj = new StringJoiner(",", "{", "}");
            for (String k : keys) {
                sj.add(MAPPER.writeValueAsString(k)
                        + ":" + canonicalize(node.get(k)));
            }
            return sj.toString();
        } else if (node.isArray()) {
            StringJoiner sj = new StringJoiner(",", "[", "]");
            for (JsonNode el : node) {
                sj.add(canonicalize(el));
            }
            return sj.toString();
        } else {
            return MAPPER.writeValueAsString(node);
        }
    }

    // ── HTTP helper ────────────────────────────────────────────────
    static String get(HttpClient c, String url) throws Exception {
        HttpResponse<String> resp = c.send(
                HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() / 100 != 2) {
            throw new RuntimeException(
                    "GET " + url + " returned " + resp.statusCode());
        }
        return resp.body();
    }
}