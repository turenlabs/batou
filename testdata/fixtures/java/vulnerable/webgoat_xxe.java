// WebGoat XXE - XML External Entity Processing
// Expected: GTSS-XXE-001 (Java XXE)
// CWE-611, OWASP A05
package com.webgoat.lessons;

import java.io.StringReader;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;

public class XXELesson {

    public String parseXML(HttpServletRequest request) throws Exception {
        String xmlInput = request.getParameter("xml");

        // VULNERABLE: WebGoat XXE - parsing user XML without disabling external entities
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        org.w3c.dom.Document doc = builder.parse(new InputSource(new StringReader(xmlInput)));

        return doc.getDocumentElement().getTextContent();
    }
}
