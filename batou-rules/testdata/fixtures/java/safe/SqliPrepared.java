package com.example.safe;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SqliPrepared extends HttpServlet {

    private Connection getConnection() throws Exception {
        return DriverManager.getConnection(
                System.getenv("JDBC_URL"),
                System.getenv("DB_USER"),
                System.getenv("DB_PASS")
        );
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String userId = request.getParameter("id");
        try {
            Connection conn = getConnection();
            PreparedStatement ps = conn.prepareStatement(
                    "SELECT id, username, email FROM users WHERE id = ?");
            ps.setString(1, userId);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                response.getWriter().println(rs.getString("username"));
            }
            rs.close();
            ps.close();
            conn.close();
        } catch (Exception e) {
            response.sendError(500, "Database error");
        }
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String name = request.getParameter("name");
        String email = request.getParameter("email");
        try {
            Connection conn = getConnection();
            PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO users (name, email) VALUES (?, ?)");
            ps.setString(1, name);
            ps.setString(2, email);
            ps.executeUpdate();
            ps.close();
            conn.close();
        } catch (Exception e) {
            response.sendError(500, "Database error");
        }
    }
}
