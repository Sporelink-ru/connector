package ru.sporelink.connector;

import java.sql.*;

public class Ledger {
    private final Connection conn;

    public Ledger(String path) throws SQLException {
        conn = DriverManager.getConnection("jdbc:sqlite:" + path);
        try (Statement st = conn.createStatement()) {
            st.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    player_id TEXT PRIMARY KEY,
                    balance   INTEGER NOT NULL DEFAULT 0
                )
            """);
            st.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    tx_id       TEXT PRIMARY KEY,
                    from_player TEXT,
                    to_player   TEXT,
                    amount      INTEGER NOT NULL,
                    status      TEXT NOT NULL,
                    peer_url    TEXT,
                    created_at  INTEGER NOT NULL
                )
            """);
        }
        // Migration: old DBs don't have peer_url
        try (ResultSet rs = conn.getMetaData().getColumns(null, null, "transactions", "peer_url")) {
            if (!rs.next()) {
                try (Statement st = conn.createStatement()) {
                    st.execute("ALTER TABLE transactions ADD COLUMN peer_url TEXT");
                }
            }
        }
    }

    public long balance(String playerId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT balance FROM accounts WHERE player_id = ?")) {
            ps.setString(1, playerId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getLong(1) : 0;
            }
        }
    }

    public void credit(String playerId, long amount) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("""
            INSERT INTO accounts (player_id, balance) VALUES (?, ?)
            ON CONFLICT(player_id) DO UPDATE SET balance = balance + excluded.balance
        """)) {
            ps.setString(1, playerId);
            ps.setLong(2, amount);
            ps.executeUpdate();
        }
    }

    // ── 2PC: sender side ───────────────────────────────────────────
    public boolean prepareOut(String txId, String fromPlayer, long amount, String peerUrl)
            throws SQLException {
        conn.setAutoCommit(false);
        try {
            long bal = balance(fromPlayer);
            if (bal < amount) {
                conn.rollback();
                conn.setAutoCommit(true);
                return false;
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE accounts SET balance = balance - ? WHERE player_id = ?")) {
                ps.setLong(1, amount);
                ps.setString(2, fromPlayer);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = conn.prepareStatement("""
                INSERT INTO transactions
                    (tx_id, from_player, to_player, amount, status, peer_url, created_at)
                VALUES (?, ?, NULL, ?, 'prepared_out', ?, ?)
            """)) {
                ps.setString(1, txId);
                ps.setString(2, fromPlayer);
                ps.setLong(3, amount);
                ps.setString(4, peerUrl);
                ps.setLong(5, System.currentTimeMillis() / 1000);
                ps.executeUpdate();
            }
            conn.commit();
            return true;
        } catch (SQLException e) {
            conn.rollback();
            throw e;
        } finally {
            conn.setAutoCommit(true);
        }
    }

    public void commitOut(String txId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE transactions SET status = 'committed' "
              + "WHERE tx_id = ? AND status = 'prepared_out'")) {
            ps.setString(1, txId);
            ps.executeUpdate();
        }
    }

    public void rollbackOut(String txId) throws SQLException {
        conn.setAutoCommit(false);
        try {
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT from_player, amount FROM transactions "
                  + "WHERE tx_id = ? AND status = 'prepared_out'")) {
                ps.setString(1, txId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        credit(rs.getString(1), rs.getLong(2));
                    }
                }
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE transactions SET status = 'rolled_back' "
                  + "WHERE tx_id = ? AND status = 'prepared_out'")) {
                ps.setString(1, txId);
                ps.executeUpdate();
            }
            conn.commit();
        } catch (SQLException e) {
            conn.rollback();
            throw e;
        } finally {
            conn.setAutoCommit(true);
        }
    }

    // ── 2PC: receiver side ─────────────────────────────────────────
    public void prepareIn(String txId, String toPlayer, long amount, String peerUrl)
            throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("""
            INSERT INTO transactions
                (tx_id, from_player, to_player, amount, status, peer_url, created_at)
            VALUES (?, NULL, ?, ?, 'prepared_in', ?, ?)
        """)) {
            ps.setString(1, txId);
            ps.setString(2, toPlayer);
            ps.setLong(3, amount);
            ps.setString(4, peerUrl);
            ps.setLong(5, System.currentTimeMillis() / 1000);
            ps.executeUpdate();
        }
    }

    public boolean commitIn(String txId) throws SQLException {
        conn.setAutoCommit(false);
        try {
            String to = null;
            long amount = 0;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT to_player, amount FROM transactions "
                  + "WHERE tx_id = ? AND status = 'prepared_in'")) {
                ps.setString(1, txId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        // Idempotent: already committed?
                        conn.rollback();
                        conn.setAutoCommit(true);
                        return "committed".equals(getTxStatus(txId));
                    }
                    to = rs.getString(1);
                    amount = rs.getLong(2);
                }
            }
            credit(to, amount);
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE transactions SET status = 'committed' "
                  + "WHERE tx_id = ? AND status = 'prepared_in'")) {
                ps.setString(1, txId);
                ps.executeUpdate();
            }
            conn.commit();
            return true;
        } catch (SQLException e) {
            conn.rollback();
            throw e;
        } finally {
            conn.setAutoCommit(true);
        }
    }

    public void rollbackIn(String txId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE transactions SET status = 'rolled_back' "
              + "WHERE tx_id = ? AND status = 'prepared_in'")) {
            ps.setString(1, txId);
            ps.executeUpdate();
        }
    }

    public String getTxStatus(String txId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT status FROM transactions WHERE tx_id = ?")) {
            ps.setString(1, txId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    public void close() throws SQLException {
        conn.close();
    }
}