# Source: CWE-78 - OS Command Injection in Ruby
# Expected: GTSS-INJ-002 (Command Injection via system/backticks)
# OWASP: A03:2021 - Injection (OS Command Injection)

class ToolsController < ApplicationController
  def ping
    host = params[:host]
    result = `ping -c 4 #{host}`
    render json: { output: result }
  end

  def whois
    domain = params[:domain]
    result = system("whois #{domain}")
    render json: { output: result }
  end

  def convert_image
    input_path = params[:file_path]
    format = params[:format]
    output_path = input_path.sub(/\.\w+$/, ".#{format}")
    %x(convert #{input_path} #{output_path})
    send_file output_path
  end
end
