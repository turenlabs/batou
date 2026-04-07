// Source: CWE-611 - Improper restriction of XML external entity reference
// Expected: BATOU-GEN-003 (XXE - XML External Entity), BATOU-XXE-001, BATOU-JAVA-013
// OWASP: A03:2021 - Injection (XXE)

package com.example.vulnerable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import java.io.InputStream;

public class A03XxeParser {

    public void parseXmlUpload(HttpServletRequest request, HttpServletResponse response) throws Exception {
        InputStream xmlInput = request.getInputStream();
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(xmlInput);
        NodeList names = doc.getElementsByTagName("name");
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < names.getLength(); i++) {
            result.append(names.item(i).getTextContent()).append("\n");
        }
        response.getWriter().write(result.toString());
    }
}
