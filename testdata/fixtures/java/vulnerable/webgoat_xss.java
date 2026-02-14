// WebGoat XSS - Reflected and Stored patterns
// Expected: GTSS-XSS-011, GTSS-XSS-014, GTSS-XSS-015
// CWE-79, OWASP A03
package com.webgoat.lessons;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CrossSiteScriptingLesson extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        PrintWriter out = response.getWriter();

        // VULNERABLE: WebGoat reflected XSS via response writer
        out.println("<html><body>");
        out.println("Hello " + name);
        out.println("</body></html>");

        // VULNERABLE: String concat HTML with user input
        String html = "<div>Welcome, " + request.getParameter("user") + "</div>";
        response.getWriter().write(html);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String comment = request.getParameter("comment");

        // VULNERABLE: Stored XSS - writing user input to page
        response.setContentType("text/html");
        response.getWriter().println("<p>" + comment + "</p>");
    }
}
