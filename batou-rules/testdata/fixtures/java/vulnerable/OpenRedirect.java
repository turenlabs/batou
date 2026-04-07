package com.example.vulnerable;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OpenRedirect extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String redirectUrl = request.getParameter("url");
        response.sendRedirect(redirectUrl);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String returnTo = request.getParameter("returnTo");
        if (returnTo != null && !returnTo.isEmpty()) {
            response.sendRedirect(returnTo);
        } else {
            response.sendRedirect("/home");
        }
    }
}
