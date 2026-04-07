# GTSS-RB-005: Kernel#open with pipe command injection

def fetch_resource
  # Vulnerable: open with params allows pipe injection
  data = open(params[:url]).read
  render text: data
end

def read_dynamic_file
  # Vulnerable: open with explicit pipe
  output = open("| whoami")
end

def fetch_uri
  # Vulnerable: URI.open with user input
  content = URI.open(params[:resource]).read
end
