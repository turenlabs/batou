// Path Traversal
// Expected: GTSS-TRV-001 (Path Traversal)
// CWE-22, OWASP A01
package com.webgoat.lessons;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PathTraversalLesson {

    public void downloadFile(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("filename");

        // VULNERABLE: Path traversal - direct user input in file path
        File file = new File("/var/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);

        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            response.getOutputStream().write(buffer, 0, bytesRead);
        }
        fis.close();
    }
}
