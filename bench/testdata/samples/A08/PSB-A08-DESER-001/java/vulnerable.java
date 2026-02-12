// PSB-A08-DESER-001: User data deserialization
// CWE: CWE-502
// Expected: GTSS-INJ-010
package com.example.prefs;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.Base64;
import java.util.Map;

@RestController
public class PreferencesController {

    @PostMapping("/api/preferences/import")
    public Map<String, Object> importPrefs(@RequestBody Map<String, String> body) throws Exception {
        String encoded = body.get("preferences");
        if (encoded == null) {
            throw new IllegalArgumentException("preferences data is required");
        }

        byte[] data = Base64.getDecoder().decode(encoded);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object preferences = ois.readObject();
        ois.close();

        // Apply preferences to user account
        @SuppressWarnings("unchecked")
        Map<String, Object> prefs = (Map<String, Object>) preferences;
        return Map.of("status", "imported", "preferences", prefs);
    }
}
