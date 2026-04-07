package com.example.vulnerable;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogInjection extends HttpServlet {

    private static final Logger logger = LoggerFactory.getLogger(LogInjection.class);

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String action = request.getParameter("action");

        logger.info("User login attempt: " + request.getParameter("username") + " action=" + action);

        if (authenticate(username, request.getParameter("password"))) {
            logger.info("Authentication successful for user: " + username);
            response.sendRedirect("/dashboard");
        } else {
            logger.warn("Failed login for user: " + username + " from IP: " + request.getRemoteAddr());
            response.sendError(401, "Invalid credentials");
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String searchTerm = request.getParameter("q");
        logger.debug("Search query from user: " + searchTerm);
        System.out.println("Search performed: " + request.getParameter("q"));
    }

    private boolean authenticate(String username, String pass) {
        return false;
    }
}
