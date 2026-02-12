// PSB-A08-DESER-001: User data deserialization
// CWE: CWE-502
// Expected: (none - secure)
package com.example.prefs;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
public class PreferencesController {

    private static final Set<String> ALLOWED_KEYS = Set.of(
        "theme", "language", "timezone", "notifications", "font_size"
    );

    private final ObjectMapper mapper = new ObjectMapper();

    @PostMapping("/api/preferences/import")
    public Map<String, Object> importPrefs(@RequestBody Map<String, Object> body) throws Exception {
        Object raw = body.get("preferences");
        if (raw == null) {
            throw new IllegalArgumentException("preferences data is required");
        }

        Map<String, Object> parsed;
        if (raw instanceof String) {
            parsed = mapper.readValue((String) raw, Map.class);
        } else if (raw instanceof Map) {
            parsed = (Map<String, Object>) raw;
        } else {
            throw new IllegalArgumentException("invalid preferences format");
        }

        Map<String, Object> safePrefs = new HashMap<>();
        for (Map.Entry<String, Object> entry : parsed.entrySet()) {
            if (ALLOWED_KEYS.contains(entry.getKey())) {
                safePrefs.put(entry.getKey(), entry.getValue());
            }
        }

        return Map.of("status", "imported", "preferences", safePrefs);
    }
}
