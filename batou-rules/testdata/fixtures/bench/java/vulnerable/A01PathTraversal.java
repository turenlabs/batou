// Source: OWASP WebGoat - File upload path traversal
// Expected: BATOU-TRV-001 (Path Traversal)
// OWASP: A01:2021 - Broken Access Control (Path Traversal)

package com.example.vulnerable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;

public class A01PathTraversal {

    private static final String UPLOAD_DIR = "/var/uploads";

    public void downloadFile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String fileName = request.getParameter("file");
        File file = new File(UPLOAD_DIR, fileName);
        if (!file.exists()) {
            response.sendError(404, "File not found");
            return;
        }
        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
        FileInputStream fis = new FileInputStream(file);
        OutputStream os = response.getOutputStream();
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            os.write(buffer, 0, bytesRead);
        }
        fis.close();
    }
}
