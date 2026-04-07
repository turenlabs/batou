package com.example.safe;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Safe patterns: all user input is escaped before embedding in HTML.
 */
public class XssHtmlSafe extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String name = request.getParameter("name");
        String query = request.getParameter("q");

        // Safe: using OWASP encoder before concatenation
        StringBuilder cart = new StringBuilder();
        cart.append("<div class='cart'>" + Encode.forHtml(name) + "</div>");

        // Safe: escaped before concat
        String safeName = Encode.forHtml(name);
        String html = "<h1>" + safeName + "</h1>";

        // Safe: response writer with encoded output
        response.getWriter().println("<div class='result'>" + Encode.forHtml(query) + "</div>");

        // Safe: String.format with pre-escaped values
        String safeQuery = Encode.forHtml(query);
        String formatted = String.format("<p>Results for %s</p>", safeQuery);
        response.getWriter().write(formatted);
    }

    // Safe: static HTML with no user input
    protected void renderStatic(HttpServletResponse response) throws IOException {
        response.getWriter().println("<div class='footer'>Copyright 2024</div>");
        StringBuilder sb = new StringBuilder();
        sb.append("<nav>" + "Home" + "</nav>");
    }
}
