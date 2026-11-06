package ru.sporelink.connector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;

public class NodeApp {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();
    private static final long TS_WINDOW = 300;
    private static final Map<String, Ed25519PublicKeyParameters> PEER_KEYS = new HashMap<>();

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("usage: NodeApp <port> <data-dir> <node-id>");
            System.exit(2);
        }
        int port = Integer.parseInt(args[0]);
        String dataDir = args[1];
        String nodeId = args[2];
        String selfUrl = "http://localhost:" + port;

        NodeKey key = NodeKey.loadOrCreate(dataDir + "/node-key.txt");
        Ledger ledger = new Ledger(dataDir + "/ledger.db");

        System.out.println("Node ID:  " + nodeId);
        System.out.println("Pubkey:   ed25519:" + key.publicKeyBase64());

        // Recovery loop
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(() -> {
            try {
                for (Ledger.StuckTx tx : ledger.findPreparedOutOlderThan(30)) {
                    System.out.println("[recovery] stuck tx " + tx.txId() + " peer=" + tx.peerUrl());
                    try {
                        String body = "{\"tx_id\":\"" + tx.txId()
                                + "\",\"from_node\":\"" + selfUrl + "\"}";
                        HttpResponse<String> r = signedPost(key, nodeId,
                                tx.peerUrl() + "/tx/commit", "/tx/commit", body);
                        if (r.statusCode() / 100 == 2) {
                            ledger.commitOut(tx.txId());
                            System.out.println("[recovery] ✓ committed " + tx.txId());
                        } else {
                            System.out.println("[recovery] peer says: " + r.body());
                        }
                    } catch (Exception e) {
                        System.out.println("[recovery] peer unreachable: " + e.getMessage());
                    }
                }
            } catch (Exception e) {
                System.err.println("[recovery] error: " + e.getMessage());
            }
        }, 15, 15, java.util.concurrent.TimeUnit.SECONDS);

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newCachedThreadPool()); // ← КРИТИЧНО

        server.createContext("/.well-known/sporelink-node", ex -> respond(ex, 200,
                "{\"node_id\":\"" + nodeId
              + "\",\"public_key\":\"ed25519:" + key.publicKeyBase64()
              + "\",\"endpoint\":\"" + selfUrl + "\"}"));

        server.createContext("/balance/", ex -> {
            try {
                String id = pathSuffix(ex, "/balance/");
                long bal = ledger.balance(id);
                respond(ex, 200, "{\"player_id\":\"" + id + "\",\"balance\":" + bal + "}");
            } catch (Exception e) { respond(ex, 500, err(e)); }
        });

        server.createContext("/credit/", ex -> {
            if (!isPost(ex)) { respond(ex, 405, "{\"error\":\"POST only\"}"); return; }
            try {
                String id = pathSuffix(ex, "/credit/");
                JsonNode b = MAPPER.readTree(ex.getRequestBody());
                ledger.credit(id, b.get("amount").asLong());
                respond(ex, 200, "{\"player_id\":\"" + id + "\",\"balance\":"
                        + ledger.balance(id) + "}");
            } catch (Exception e) { respond(ex, 500, err(e)); }
        });

        // ── Signed 2PC endpoints ───────────────────────────────────
        server.createContext("/tx/prepare", ex -> {
            if (!isPost(ex)) { respond(ex, 405, "{\"error\":\"POST only\"}"); return; }
            byte[] body;
            try { body = verifySigned(ex); }
            catch (AuthException e) { respond(ex, 401, "{\"error\":\"" + esc(e.getMessage()) + "\"}"); return; }
            try {
                JsonNode b = MAPPER.readTree(body);
                ledger.prepareIn(
                        b.get("tx_id").asText(),
                        b.get("to").asText(),
                        b.get("amount").asLong(),
                        b.get("from_node").asText(""));
                respond(ex, 200, "{\"status\":\"prepared\"}");
            } catch (Exception e) { respond(ex, 500, err(e)); }
        });

        server.createContext("/tx/commit", ex -> {
            if (!isPost(ex)) { respond(ex, 405, "{\"error\":\"POST only\"}"); return; }
            byte[] body;
            try { body = verifySigned(ex); }
            catch (AuthException e) { respond(ex, 401, "{\"error\":\"" + esc(e.getMessage()) + "\"}"); return; }
            try {
                JsonNode b = MAPPER.readTree(body);
                boolean ok = ledger.commitIn(b.get("tx_id").asText());
                respond(ex, ok ? 200 : 409,
                        ok ? "{\"status\":\"committed\"}"
                           : "{\"error\":\"unknown or not prepared\"}");
            } catch (Exception e) { respond(ex, 500, err(e)); }
        });

        server.createContext("/tx/rollback", ex -> {
            if (!isPost(ex)) { respond(ex, 405, "{\"error\":\"POST only\"}"); return; }
            byte[] body;
            try { body = verifySigned(ex); }
            catch (AuthException e) { respond(ex, 401, "{\"error\":\"" + esc(e.getMessage()) + "\"}"); return; }
            try {
                JsonNode b = MAPPER.readTree(body);
                ledger.rollbackIn(b.get("tx_id").asText());
                respond(ex, 200, "{\"status\":\"rolled_back\"}");
            } catch (Exception e) { respond(ex, 500, err(e)); }
        });

        server.createContext("/tx/status/", ex -> {
            try {
                String txId = pathSuffix(ex, "/tx/status/");
                String s = ledger.getTxStatus(txId);
                if (s == null) respond(ex, 404, "{\"error\":\"not found\"}");
                else respond(ex, 200, "{\"tx_id\":\"" + txId + "\",\"status\":\"" + s + "\"}");
            } catch (Exception e) { respond(ex, 500, err(e)); }
        });

        server.createContext("/transfer", ex -> {
            if (!isPost(ex)) { respond(ex, 405, "{\"error\":\"POST only\"}"); return; }
            try {
                JsonNode b = MAPPER.readTree(ex.getRequestBody());
                String toNode = b.get("to_node").asText().replaceAll("/+$", "");
                String from   = b.get("from").asText();
                String to     = b.get("to").asText();
                long   amount = b.get("amount").asLong();
                String txId   = UUID.randomUUID().toString();

                if (!ledger.prepareOut(txId, from, amount, toNode)) {
                    respond(ex, 400, "{\"error\":\"insufficient balance\",\"tx_id\":\"" + txId + "\"}");
                    return;
                }

                String prepBody = String.format(
                        "{\"tx_id\":\"%s\",\"to\":\"%s\",\"amount\":%d,\"from_node\":\"%s\"}",
                        txId, to, amount, selfUrl);
                HttpResponse<String> prepResp;
                try {
                    prepResp = signedPost(key, nodeId,
                            toNode + "/tx/prepare", "/tx/prepare", prepBody);
                } catch (Exception e) {
                    ledger.rollbackOut(txId);
                    respond(ex, 502, "{\"error\":\"peer unreachable — rolled back\",\"tx_id\":\""
                            + txId + "\"}");
                    return;
                }
                if (prepResp.statusCode() / 100 != 2) {
                    ledger.rollbackOut(txId);
                    respond(ex, 502,
                            "{\"error\":\"peer rejected prepare — rolled back\",\"tx_id\":\""
                            + txId + "\",\"peer\":\"" + esc(prepResp.body()) + "\"}");
                    return;
                }

                // ── Commit (with from_node in body for peer key discovery) ──
                String commitBody = "{\"tx_id\":\"" + txId
                        + "\",\"from_node\":\"" + selfUrl + "\"}";
                boolean commitOk = false;
                String lastErr = "";
                for (int i = 0; i < 3; i++) {
                    try {
                        HttpResponse<String> cr = signedPost(key, nodeId,
                                toNode + "/tx/commit", "/tx/commit", commitBody);
                        if (cr.statusCode() / 100 == 2) { commitOk = true; break; }
                        lastErr = "status " + cr.statusCode() + ": " + cr.body();
                    } catch (Exception e) { lastErr = e.getMessage(); }
                    Thread.sleep(500);
                }
                if (!commitOk) {
                    respond(ex, 202,
                            "{\"error\":\"commit pending — recovery will retry\","
                          + "\"tx_id\":\"" + txId + "\",\"detail\":\"" + esc(lastErr) + "\"}");
                    return;
                }
                ledger.commitOut(txId);
                respond(ex, 200, "{\"status\":\"committed\",\"tx_id\":\"" + txId + "\"}");
            } catch (Exception e) { respond(ex, 500, err(e)); }
        });

        server.start();
        System.out.println("Listening on " + selfUrl);
    }

    // ── Signed POST ────────────────────────────────────────────────
    private static HttpResponse<String> signedPost(
            NodeKey key, String nodeId,
            String url, String path, String body) throws Exception {
        long ts = System.currentTimeMillis() / 1000;
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        String sig = Signer.sign(key, "POST", path, ts, bodyBytes);
        return HTTP.send(
                HttpRequest.newBuilder(URI.create(url))
                        .header("Content-Type", "application/json")
                        .header("X-Sporelink-Node-Id", nodeId)
                        .header("X-Sporelink-Timestamp", String.valueOf(ts))
                        .header("X-Sporelink-Signature", sig)
                        .POST(HttpRequest.BodyPublishers.ofByteArray(bodyBytes))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    // ── Verify signed request, return buffered body ────────────────
    private static byte[] verifySigned(HttpExchange ex) throws AuthException {
        try {
            byte[] body = ex.getRequestBody().readAllBytes();
            String peerNodeId = ex.getRequestHeaders().getFirst("X-Sporelink-Node-Id");
            String tsStr      = ex.getRequestHeaders().getFirst("X-Sporelink-Timestamp");
            String sigB64     = ex.getRequestHeaders().getFirst("X-Sporelink-Signature");
            if (peerNodeId == null || tsStr == null || sigB64 == null)
                throw new AuthException("missing headers");

            long ts = Long.parseLong(tsStr);
            long now = System.currentTimeMillis() / 1000;
            if (Math.abs(now - ts) > TS_WINDOW)
                throw new AuthException("timestamp out of window");

            Ed25519PublicKeyParameters pub = PEER_KEYS.get(peerNodeId);
            if (pub == null) {
                String peerUrl = null;
                try {
                    JsonNode b = MAPPER.readTree(body);
                    if (b.hasNonNull("from_node")) peerUrl = b.get("from_node").asText();
                } catch (Exception ignored) {}
                if (peerUrl == null)
                    throw new AuthException("unknown peer " + peerNodeId);

                String wkBody = HTTP.send(
                        HttpRequest.newBuilder(
                                URI.create(peerUrl + "/.well-known/sporelink-node"))
                                .GET().build(),
                        HttpResponse.BodyHandlers.ofString()).body();
                JsonNode wk = MAPPER.readTree(wkBody);
                String pkB64 = wk.get("public_key").asText().replace("ed25519:", "");
                pub = new Ed25519PublicKeyParameters(Base64.getDecoder().decode(pkB64), 0);
                PEER_KEYS.put(peerNodeId, pub);
                System.out.println("[verify] cached pubkey for " + peerNodeId);
            }

            if (!Signer.verify(pub, ex.getRequestMethod(),
                    ex.getRequestURI().getPath(), ts, body, sigB64))
                throw new AuthException("signature mismatch");
            return body;
        } catch (AuthException ae) {
            throw ae;
        } catch (Exception e) {
            throw new AuthException(e.getMessage() == null
                    ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    static class AuthException extends Exception {
        AuthException(String msg) { super(msg); }
    }

    private static String pathSuffix(HttpExchange ex, String prefix) {
        return ex.getRequestURI().getPath().substring(prefix.length());
    }
    private static boolean isPost(HttpExchange ex) {
        return "POST".equals(ex.getRequestMethod());
    }
    private static String err(Exception e) {
        return "{\"error\":\"" + esc(e.getMessage() == null
                ? e.getClass().getSimpleName() : e.getMessage()) + "\"}";
    }
    private static String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", " ").replace("\r", "");
    }
    private static void respond(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }
}