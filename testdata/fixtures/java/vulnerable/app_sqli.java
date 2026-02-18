// SQL Injection - String concatenation pattern
// Expected: GTSS-INJ-001 (SQL Injection)
// CWE-89, OWASP A03
package com.webgoat.lessons;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqlInjectionLesson {

    public String executeQuery(HttpServletRequest request, Connection connection) throws Exception {
        String accountName = request.getParameter("account_name");

        // VULNERABLE: Classic string concatenation SQL injection
        Statement statement = connection.createStatement();
        ResultSet results = statement.executeQuery(
            "SELECT * FROM user_data WHERE last_name = '" + accountName + "'");

        StringBuilder sb = new StringBuilder();
        while (results.next()) {
            sb.append(results.getString("first_name")).append(" ");
        }
        return sb.toString();
    }

    public String orderByInjection(HttpServletRequest request, Connection connection) throws Exception {
        String column = request.getParameter("column");

        // VULNERABLE: ORDER BY injection
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM employees ORDER BY " + column);

        return rs.toString();
    }
}
