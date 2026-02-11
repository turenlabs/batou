// Source: OWASP WebGoat - SQL injection in login
// Expected: GTSS-INJ-001 (SQL Injection via string concatenation)
// OWASP: A03:2021 - Injection (SQL Injection)

package com.example.vulnerable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class A03SqlInjection {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/app";

    public void searchProducts(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String searchTerm = request.getParameter("q");
        Connection conn = DriverManager.getConnection(DB_URL, "app", "password");
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
        ResultSet rs = stmt.executeQuery(sql);
        StringBuilder sb = new StringBuilder("[");
        while (rs.next()) {
            sb.append("{\"id\":").append(rs.getInt("id"))
              .append(",\"name\":\"").append(rs.getString("name")).append("\"},");
        }
        sb.append("]");
        response.getWriter().write(sb.toString());
        conn.close();
    }
}
