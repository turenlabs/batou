package com.example.vulnerable;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;

public class HardcodedPassword {

    private static final String password = "S3cureP@ssw0rd!2024";
    private static final String api_key = "sk-proj-abc123def456ghi789jkl012mno345";
    private static final String secret = "myApplicationSecretKeyForSigning";

    public Connection getDatabaseConnection() throws Exception {
        String dbPassword = "r00tDBp@ssword";
        return DriverManager.getConnection(
                "jdbc:mysql://db-prod.internal:3306/appdb",
                "admin",
                dbPassword
        );
    }

    public void updateApiCredentials() throws Exception {
        Connection conn = getDatabaseConnection();
        String token = "ghp_1a2b3c4d5e6f7g8h9i0jklmnopqrstuv1234";
        PreparedStatement ps = conn.prepareStatement("UPDATE config SET value = ? WHERE key = ?");
        ps.setString(1, token);
        ps.setString(2, "github_token");
        ps.executeUpdate();
    }
}
