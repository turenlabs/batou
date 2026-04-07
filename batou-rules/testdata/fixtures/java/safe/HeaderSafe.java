package com.example.safe;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// SAFE: Response headers with sanitized values to prevent header injection.
// Should NOT trigger BATOU-HDR-001 or any header injection rules.

public class HeaderSafe extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String filename = request.getParameter("file");

        // Sanitize: strip CR/LF to prevent header injection
        String safeName = sanitizeHeaderValue(filename);

        response.setHeader("Content-Disposition", "attachment; filename=\"" + safeName + "\"");
        response.setContentType("application/octet-stream");
        response.getWriter().write("file content");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String redirectPath = request.getParameter("next");

        // Sanitize and validate redirect target
        String safePath = sanitizeHeaderValue(redirectPath);
        if (!safePath.startsWith("/")) {
            response.sendError(400, "Invalid redirect");
            return;
        }

        response.setHeader("Location", safePath);
        response.setStatus(302);
    }

    private String sanitizeHeaderValue(String value) {
        if (value == null) {
            return "";
        }
        // Remove CR, LF, and null bytes
        return value.replaceAll("[\\r\\n\\0]", "");
    }
}
