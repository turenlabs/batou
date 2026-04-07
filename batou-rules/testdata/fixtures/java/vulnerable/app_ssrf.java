// SSRF via user-controlled URL
// Expected: GTSS-SSRF-001, GTSS-JAVA-016
// CWE-918, OWASP A10
package com.webgoat.lessons;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;

public class SSRFLesson {

    public String fetchURL(HttpServletRequest request) throws Exception {
        String targetUrl = request.getParameter("url");

        // VULNERABLE: SSRF - opening user-controlled URL
        URL url = new URL(targetUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

        StringBuilder content = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null) {
            content.append(line);
        }
        in.close();
        return content.toString();
    }
}
