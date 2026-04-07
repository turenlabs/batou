package com.example.safe;

import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DeserializationSafe extends HttpServlet {

    private static final Set<String> ALLOWED_CLASSES = Set.of(
            "com.example.dto.UserProfile",
            "com.example.dto.Settings",
            "java.lang.String",
            "java.lang.Integer",
            "java.util.ArrayList"
    );

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            ObjectInputStream ois = new ObjectInputStream(request.getInputStream());

            ObjectInputFilter filter = info -> {
                if (info.serialClass() != null) {
                    String className = info.serialClass().getName();
                    if (!ALLOWED_CLASSES.contains(className)) {
                        return ObjectInputFilter.Status.REJECTED;
                    }
                }
                if (info.depth() > 5) {
                    return ObjectInputFilter.Status.REJECTED;
                }
                if (info.references() > 100) {
                    return ObjectInputFilter.Status.REJECTED;
                }
                return ObjectInputFilter.Status.ALLOWED;
            };
            ois.setObjectInputFilter(filter);

            Object userData = ois.readObject();
            ois.close();

            response.setContentType("text/plain");
            response.getWriter().println("Received: " + userData.toString());
        } catch (Exception e) {
            response.sendError(400, "Invalid or rejected object data");
        }
    }
}
