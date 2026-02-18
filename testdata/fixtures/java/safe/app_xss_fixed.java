// XSS - Fixed with proper escaping
package com.webgoat.lessons.fixed;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

public class CrossSiteScriptingFixed extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");

        // SAFE: Using OWASP Encoder for HTML escaping
        String safeName = Encode.forHtml(name);
        response.setContentType("text/html; charset=UTF-8");
        response.getWriter().println("<html><body>");
        response.getWriter().println("Hello " + safeName);
        response.getWriter().println("</body></html>");
    }
}
