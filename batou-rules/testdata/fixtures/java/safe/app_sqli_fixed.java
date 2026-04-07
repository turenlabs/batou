// SQL Injection - Fixed with PreparedStatement
package com.webgoat.lessons.fixed;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;

public class SqlInjectionFixed {

    public String executeQuery(HttpServletRequest request, Connection connection) throws Exception {
        String accountName = request.getParameter("account_name");

        // SAFE: Using PreparedStatement with parameterized query
        PreparedStatement pstmt = connection.prepareStatement(
            "SELECT * FROM user_data WHERE last_name = ?");
        pstmt.setString(1, accountName);
        ResultSet results = pstmt.executeQuery();

        StringBuilder sb = new StringBuilder();
        while (results.next()) {
            sb.append(results.getString("first_name")).append(" ");
        }
        return sb.toString();
    }
}
