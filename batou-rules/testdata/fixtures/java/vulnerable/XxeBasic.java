package com.example.vulnerable;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class XxeBasic extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(request.getInputStream());

            NodeList names = doc.getElementsByTagName("name");
            if (names.getLength() > 0) {
                String name = names.item(0).getTextContent();
                response.getWriter().println("Hello, " + name);
            }
        } catch (Exception e) {
            response.sendError(400, "Invalid XML");
        }
    }
}
