// Source: OWASP WebGoat - Reflected XSS in search
// Expected: BATOU-XSS-010 (Reflected XSS via direct response write)
// OWASP: A03:2021 - Injection (Reflected XSS)

package com.example.vulnerable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

public class A03XssReflected {

    public void search(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String query = request.getParameter("q");
        PrintWriter out = response.getWriter();
        response.setContentType("text/html");
        out.println("<html><body>");
        out.println("<h1>Search Results</h1>");
        out.println("<p>You searched for: " + query + "</p>");
        out.println("<div id='results'></div>");
        out.println("</body></html>");
    }

    public void displayError(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String message = request.getParameter("msg");
        response.setContentType("text/html");
        response.getWriter().write("<div class='error'>" + message + "</div>");
    }
}
