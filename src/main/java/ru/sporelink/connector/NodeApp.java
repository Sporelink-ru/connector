package ru.sporelink.connector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;

public class NodeApp {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: NodeApp <port> <data-dir>");
            System.exit(2);
        }
        int port = Integer.parseInt(args[0]);
        String dataDir = args[1];
        Ledger ledger = new Ledger(dataDir + "/ledger.db");

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        // ── Local ledger ───────────────────────────────────────────
        server.createContext("/balance/", ex -> {
            try {
                String id = pathSuffix(ex, "/balance/");
                long bal = ledger.balance(id);
                respond(ex, 200, "{\"player_id\":\"" + id + "\",\"balance\":" + bal + "}");
            } catch (Exception e) {
                respond(ex, 500, err(e));
            }
        });

        server.createContext("/credit/", ex -> {
            if (!isPost(ex)) { respond(ex, 405, "{\"error\":\"POST only\"}"); return; }
            try {
                String id = pathSuffix(ex, "/credit/");
                JsonNode body = MAPPER.readTree(ex.getRequestBody());
                ledger.credit(id, body.get("amount").asLong());
                respond(ex, 200,
                        "{\"player_id\":\"" + id + "\",\"balance\":"
                        + ledger.balance(id) + "}");
            } catch (Exception e) {
                respond(ex, 500, err(e));
            }
        });

        // ── 2PC: receiver side ─────────────────────────────────────
        server.createContext("/tx/prepare", ex -> {
            if (!isPost(ex)) { respond(ex, 405, "{\"error\":\"POST only\"}"); return; }
            try {
                JsonNode b = MAPPER.readTree(ex.getRequestBody());
                ledger.prepareIn(
                        b.get("tx_id").asText(),
                        b.get("to").asText(),
                        b.get("amount").asLong(),
                        b.get("from_node").asText(""));
                respond(ex, 200, "{\"status\":\"prepared\"}");
            } catch (Exception e) {
                respond(ex, 500, err(e));
            }
        });

        server.createContext("/tx/commit", ex -> {
            if (!isPost(ex)) { respond(ex, 405, "{\"error\":\"POST only\"}"); return; }
            try {
                JsonNode b = MAPPER.readTree(ex.getRequestBody());
                boolean ok = ledger.commitIn(b.get("tx_id").asText());
                respond(ex, ok ? 200 : 409,
                        ok ? "{\"status\":\"committed\"}"
                           : "{\"error\":\"unknown or not prepared\"}");
            } catch (Exception e) {
                respond(ex, 500, err(e));
            }
        });

        server.createContext("/tx/rollback", ex -> {
            if (!isPost(ex)) { respond(ex, 405, "{\"error\":\"POST only\"}"); return; }
            try {
                JsonNode b = MAPPER.readTree(ex.getRequestBody());
                ledger.rollbackIn(b.get("tx_id").asText());
                respond(ex, 200, "{\"status\":\"rolled_back\"}");
            } catch (Exception e) {
                respond(ex, 500, err(e));
            }
        });

        server.createContext("/tx/status/", ex -> {
            try {
                String txId = pathSuffix(ex, "/tx/status/");
                String s = ledger.getTxStatus(txId);
                if (s == null) respond(ex, 404, "{\"error\":\"not found\"}");
                else respond(ex, 200, "{\"tx_id\":\"" + txId + "\",\"status\":\"" + s + "\"}");
            } catch (Exception e) {
                respond(ex, 500, err(e));
            }
        });

        // ── 2PC: sender orchestration ──────────────────────────────
        server.createContext("/transfer", ex -> {
            if (!isPost(ex)) { respond(ex, 405, "{\"error\":\"POST only\"}"); return; }
            try {
                JsonNode b = MAPPER.readTree(ex.getRequestBody());
                String toNode   = b.get("to_node").asText().replaceAll("/+$", "");
                String from     = b.get("from").asText();
                String to       = b.get("to").asText();
                long   amount   = b.get("amount").asLong();
                String txId     = UUID.randomUUID().toString();

                // Phase 1a: local prepare (with escrow)
                if (!ledger.prepareOut(txId, from, amount, toNode)) {
                    respond(ex, 400,
                            "{\"error\":\"insufficient balance\",\"tx_id\":\"" + txId + "\"}");
                    return;
                }

                // Phase 1b: remote prepare
                String prepBody = String.format(
                        "{\"tx_id\":\"%s\",\"to\":\"%s\",\"amount\":%d,\"from_node\":\"http://localhost:%d\"}",
                        txId, to, amount, port);
                HttpResponse<String> prepResp;
                try {
                    prepResp = HTTP.send(
                            HttpRequest.newBuilder(URI.create(toNode + "/tx/prepare"))
                                    .header("Content-Type", "application/json")
                                    .POST(HttpRequest.BodyPublishers.ofString(prepBody))
                                    .build(),
                            HttpResponse.BodyHandlers.ofString());
                } catch (Exception e) {
                    ledger.rollbackOut(txId);
                    respond(ex, 502,
                            "{\"error\":\"peer unreachable at prepare — rolled back\","
                          + "\"tx_id\":\"" + txId + "\",\"detail\":\"" + esc(e.getMessage()) + "\"}");
                    return;
                }
                if (prepResp.statusCode() / 100 != 2) {
                    ledger.rollbackOut(txId);
                    respond(ex, 502,
                            "{\"error\":\"peer rejected prepare — rolled back\","
                          + "\"tx_id\":\"" + txId + "\",\"peer\":\"" + esc(prepResp.body()) + "\"}");
                    return;
                }

                // Phase 2: commit with retries
                String commitBody = "{\"tx_id\":\"" + txId + "\"}";
                boolean commitOk = false;
                String lastErr = "";
                for (int attempt = 1; attempt <= 3; attempt++) {
                    try {
                        HttpResponse<String> cr = HTTP.send(
                                HttpRequest.newBuilder(URI.create(toNode + "/tx/commit"))
                                        .header("Content-Type", "application/json")
                                        .POST(HttpRequest.BodyPublishers.ofString(commitBody))
                                        .build(),
                                HttpResponse.BodyHandlers.ofString());
                        if (cr.statusCode() / 100 == 2) { commitOk = true; break; }
                        lastErr = "status " + cr.statusCode() + ": " + cr.body();
                    } catch (Exception e) {
                        lastErr = e.getMessage();
                    }
                    Thread.sleep(500);
                }

                if (!commitOk) {
                    // Leave as prepared_out; recovery needed (next iteration)
                    respond(ex, 202,
                            "{\"error\":\"commit pending — recovery needed\","
                          + "\"tx_id\":\"" + txId + "\",\"detail\":\"" + esc(lastErr) + "\"}");
                    return;
                }

                ledger.commitOut(txId);
                respond(ex, 200,
                        "{\"status\":\"committed\",\"tx_id\":\"" + txId + "\"}");
            } catch (Exception e) {
                respond(ex, 500, err(e));
            }
        });

        server.start();
        System.out.println("Sporelink node on http://localhost:" + port);
        System.out.println("Ledger: " + dataDir + "/ledger.db");
    }

    private static String pathSuffix(HttpExchange ex, String prefix) {
        return ex.getRequestURI().getPath().substring(prefix.length());
    }

    private static boolean isPost(HttpExchange ex) {
        return "POST".equals(ex.getRequestMethod());
    }

    private static String err(Exception e) {
        return "{\"error\":\"" + esc(e.getMessage() == null ? e.getClass().getSimpleName()
                : e.getMessage()) + "\"}";
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", " ").replace("\r", "");
    }

    private static void respond(HttpExchange ex, int status, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }
}