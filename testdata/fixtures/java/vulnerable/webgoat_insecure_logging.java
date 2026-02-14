// WebGoat Insecure Logging
// Expected: GTSS-LOG-001, GTSS-LOG-003
// CWE-117, CWE-532, OWASP A09
package com.webgoat.lessons;

import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;

public class InsecureLoggingLesson {

    private static final Logger logger = Logger.getLogger(InsecureLoggingLesson.class.getName());

    public void login(HttpServletRequest request) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // VULNERABLE: WebGoat log injection - unsanitized user input in logs
        logger.info("Login attempt for user: " + username);

        // VULNERABLE: Sensitive data (password) in logs
        logger.info("Failed login for " + username + " with password " + password);
    }
}
