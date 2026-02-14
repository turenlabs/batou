// WebGoat Insecure Deserialization
// Expected: GTSS-GEN-002, GTSS-DESER-001
// CWE-502, OWASP A08
package com.webgoat.lessons;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;
import javax.servlet.http.HttpServletRequest;

public class InsecureDeserializationLesson {

    public Object deserializeToken(HttpServletRequest request) throws Exception {
        String token = request.getParameter("token");
        byte[] data = Base64.getDecoder().decode(token);

        // VULNERABLE: WebGoat insecure deserialization - ObjectInputStream.readObject()
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
        ois.close();

        return obj;
    }
}
