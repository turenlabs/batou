package com.example.vulnerable;

import java.io.IOException;
import java.io.ObjectInputStream;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Deserialization extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
            Object userData = ois.readObject();
            ois.close();

            response.setContentType("text/plain");
            response.getWriter().println("Received: " + userData.toString());
        } catch (ClassNotFoundException e) {
            response.sendError(400, "Invalid object data");
        }
    }
}
