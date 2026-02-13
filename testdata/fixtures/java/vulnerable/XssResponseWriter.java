package com.example.vulnerable;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Demonstrates Java response writer XSS vulnerabilities:
 * HttpServletResponse.getWriter(), String.format with HTML, Spring @ResponseBody.
 */
public class XssResponseWriter extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String name = request.getParameter("name");
        String query = request.getParameter("q");

        // response.getWriter().println with HTML + user input
        response.getWriter().println("<div class='result'>" + name + "</div>");
        response.getWriter().write("<span class='query'>" + query + "</span>");

        // String.format with HTML template and user parameters
        String html = String.format("<h1>Welcome %s</h1><p>Results for %s</p>", name, query);
        response.getWriter().write(html);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String feedback = request.getParameter("feedback");

        // response.getOutputStream().write pattern
        String output = String.format("<div class='feedback'>%s</div>", feedback);
        response.getWriter().println(output);
    }
}
