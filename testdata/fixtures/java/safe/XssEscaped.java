package com.example.safe;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

public class XssEscaped extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String name = request.getParameter("name");
        String query = request.getParameter("q");

        response.setContentType("text/html; charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>Hello, " + Encode.forHtml(name) + "</h1>");
        out.println("<p>Search results for: " + Encode.forHtml(query) + "</p>");
        out.println("</body></html>");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String feedback = request.getParameter("feedback");
        String safeFeedback = Encode.forHtml(feedback);
        PrintWriter writer = response.getWriter();
        writer.write("<div class='feedback'>" + safeFeedback + "</div>");
    }
}
