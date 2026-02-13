# GTSS-RB-003: Unsafe YAML.load

def parse_user_config(data)
  # Vulnerable: YAML.load deserializes arbitrary objects
  config = YAML.load(data)
  apply_config(config)
end

def load_uploaded_config(path)
  # Vulnerable: YAML.load_file with user-controlled path
  settings = YAML.load_file(path)
  settings
end
