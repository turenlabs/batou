package com.example.vulnerable;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Demonstrates Java HTML string concatenation XSS vulnerabilities.
 * Modeled after WebGoat CrossSiteScriptingLesson5a.java patterns.
 */
public class XssStringConcat extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String field1 = request.getParameter("field1");
        String field2 = request.getParameter("field2");

        // StringBuilder.append with HTML + user input concatenation
        StringBuilder cart = new StringBuilder();
        cart.append("<div class='cart'>" + field1 + "</div>");
        cart.append("We have charged credit card:" + field1 + "<br />");

        // String concatenation with HTML tags and user input
        String html = "<h1>" + field2 + "</h1>";
        String page = "<p>Welcome, " + field1 + "</p>";

        PrintWriter out = response.getWriter();
        out.println(cart.toString());
        out.println(html);
        out.println(page);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String comment = request.getParameter("comment");
        String username = request.getParameter("user");

        // Stored XSS via StringBuilder
        StringBuilder output = new StringBuilder();
        output.append("<div class='comment'>" + comment + "</div>");
        output.append("<span class='author'>" + username + "</span>");

        response.getWriter().write(output.toString());
    }
}
