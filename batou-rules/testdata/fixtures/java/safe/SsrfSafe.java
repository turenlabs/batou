package com.example.safe;

import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// SAFE: URL validation against allowlist before making outbound requests.
// Should NOT trigger BATOU-SSRF-001 or any SSRF rules.

public class SsrfSafe extends HttpServlet {

    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(
            Arrays.asList("api.example.com", "cdn.example.com", "service.internal"));

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String target = request.getParameter("url");

        URL url = new URL(target);

        // Validate host against allowlist
        if (!ALLOWED_HOSTS.contains(url.getHost())) {
            response.sendError(403, "Host not allowed");
            return;
        }

        // Safe: only allowlisted hosts are fetched
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        response.setStatus(conn.getResponseCode());
        response.getWriter().write("Fetched from: " + url.getHost());
    }
}
