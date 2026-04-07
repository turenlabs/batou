package com.example.vulnerable;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Simulates a JSP page with unescaped output.
 * In real JSP, this would be: <%= request.getParameter("name") %>
 * The servlet equivalent demonstrates the same vulnerability.
 */
public class XssJsp extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String errorMsg = request.getParameter("error");
        String username = request.getParameter("user");

        response.setContentType("text/html");
        // Simulates JSP expression tag: <%= request.getParameter("error") %>
        response.getWriter().println("<div class='error'>" + errorMsg + "</div>");
        response.getWriter().write("<span>" + username + "</span>");
    }
}
