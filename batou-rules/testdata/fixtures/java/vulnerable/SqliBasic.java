package com.example.vulnerable;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SqliBasic extends HttpServlet {

    private Connection getConnection() throws Exception {
        return DriverManager.getConnection("jdbc:mysql://localhost:3306/appdb", "app", "dbpass");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String userId = request.getParameter("id");
        try {
            Connection conn = getConnection();
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE id = '" + userId + "'";
            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                response.getWriter().println(rs.getString("username"));
            }
            rs.close();
            stmt.close();
            conn.close();
        } catch (Exception e) {
            response.sendError(500, "Database error");
        }
    }
}
