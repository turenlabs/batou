# Safe: Using YAML.safe_load instead of YAML.load

def parse_config(data)
  # Safe: YAML.safe_load only allows basic types
  config = YAML.safe_load(data)
  apply_config(config)
end

def load_settings(path)
  # Safe: YAML.safe_load_file restricts deserialization
  settings = YAML.safe_load_file(path)
  settings
end
