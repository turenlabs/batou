package org.owasp.benchmark.testcode;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

// Vulnerable: DocumentBuilderFactory is created without disabling DOCTYPE
// declarations / external entities, then used to parse attacker-controlled XML.
// Detected structurally at the AST tier as CWE-611 (BATOU-JAVAAST-006).
public class XxeUnhardenedFactory {
    public void handle(HttpServletRequest req) throws Exception {
        String xml = req.getParameter("xml");
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(xml);
    }
}
