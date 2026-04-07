package vulnerable

import (
	"io"
	"net/http"

	"gopkg.in/yaml.v3"
)

// VULN: YAML deserialization from untrusted HTTP request body.
// yaml.v3 supports custom tag handlers via yaml.Unmarshaler interface,
// enabling type confusion and potential code execution.

type AppConfig struct {
	Debug    bool   `yaml:"debug"`
	AdminKey string `yaml:"admin_key"`
}

func HandleYAMLConfig(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var config AppConfig
	yaml.Unmarshal(body, &config)

	w.Write([]byte("config loaded"))
}
