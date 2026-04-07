package com.example.safe;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CommandSafe extends HttpServlet {

    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(
            Arrays.asList("status", "version", "health"));

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String action = request.getParameter("action");

        if (!ALLOWED_COMMANDS.contains(action)) {
            response.sendError(400, "Invalid action");
            return;
        }

        ProcessBuilder pb = new ProcessBuilder("/usr/local/bin/app-tool", "--action", action);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
        String line;
        StringBuilder output = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }

        response.setContentType("text/plain");
        response.getWriter().write(output.toString());
    }
}
