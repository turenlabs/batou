package com.example.safe;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeFileDownload {

    private static final String UPLOAD_DIR = "/var/www/uploads";
    private static final Set<String> ALLOWED_FILES = Set.of(
        "report.pdf", "readme.txt", "logo.png"
    );

    // SAFE: Path canonicalized and checked with startsWith
    public void downloadFile(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String fileName = req.getParameter("name");
        Path resolved = Paths.get(UPLOAD_DIR, fileName).toRealPath();
        String canonical = resolved.toFile().getCanonicalPath();

        if (!canonical.startsWith(UPLOAD_DIR)) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }

        File file = resolved.toFile();
        if (!file.exists()) {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        resp.setContentType("application/octet-stream");
        resp.setHeader("Content-Disposition", "attachment; filename=\"" + file.getName() + "\"");
        java.nio.file.Files.copy(resolved, resp.getOutputStream());
    }

    // SAFE: Allowlist of permitted file names
    public void serveStaticFile(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("file");
        if (!ALLOWED_FILES.contains(name)) {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        Path safePath = Paths.get(UPLOAD_DIR, name);
        java.nio.file.Files.copy(safePath, resp.getOutputStream());
    }
}
