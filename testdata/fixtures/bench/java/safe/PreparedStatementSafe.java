package com.example.safe;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PreparedStatementSafe {

    // SAFE: PreparedStatement with parameterized query
    public List<String> findUsers(Connection conn, HttpServletRequest req) throws SQLException {
        String name = req.getParameter("name");
        PreparedStatement stmt = conn.prepareStatement(
            "SELECT id, username, email FROM users WHERE username LIKE ? AND active = true"
        );
        stmt.setString(1, "%" + name + "%");
        ResultSet rs = stmt.executeQuery();

        List<String> results = new ArrayList<>();
        while (rs.next()) {
            results.add(rs.getString("username"));
        }
        rs.close();
        stmt.close();
        return results;
    }

    // SAFE: Parameterized INSERT
    public int createUser(Connection conn, String name, String email) throws SQLException {
        PreparedStatement stmt = conn.prepareStatement(
            "INSERT INTO users (name, email, created_at) VALUES (?, ?, NOW())",
            PreparedStatement.RETURN_GENERATED_KEYS
        );
        stmt.setString(1, name);
        stmt.setString(2, email);
        stmt.executeUpdate();

        ResultSet keys = stmt.getGeneratedKeys();
        keys.next();
        int id = keys.getInt(1);
        keys.close();
        stmt.close();
        return id;
    }

    // SAFE: Parameterized UPDATE
    public void updateProfile(Connection conn, HttpServletRequest req) throws SQLException {
        String userId = req.getParameter("id");
        String bio = req.getParameter("bio");
        PreparedStatement stmt = conn.prepareStatement(
            "UPDATE profiles SET bio = ?, updated_at = NOW() WHERE user_id = ?"
        );
        stmt.setString(1, bio);
        stmt.setString(2, userId);
        stmt.executeUpdate();
        stmt.close();
    }

    // SAFE: Parameterized DELETE
    public void deleteComment(Connection conn, String commentId, String authorId) throws SQLException {
        PreparedStatement stmt = conn.prepareStatement(
            "DELETE FROM comments WHERE id = ? AND author_id = ?"
        );
        stmt.setString(1, commentId);
        stmt.setString(2, authorId);
        stmt.executeUpdate();
        stmt.close();
    }
}
