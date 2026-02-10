package com.example.safe;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PathSafe extends HttpServlet {

    private static final String UPLOAD_DIR = "/var/uploads";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String filename = request.getParameter("file");

        Path basePath = Paths.get(UPLOAD_DIR).toRealPath();
        Path resolvedPath = basePath.resolve(filename).normalize().toRealPath();

        if (!resolvedPath.startsWith(basePath)) {
            response.sendError(403, "Access denied: path traversal detected");
            return;
        }

        File file = resolvedPath.toFile();
        if (!file.exists() || !file.isFile()) {
            response.sendError(404, "File not found");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition",
                "attachment; filename=\"" + file.getName() + "\"");

        try (FileInputStream fis = new FileInputStream(file);
             OutputStream os = response.getOutputStream()) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
        }
    }
}
