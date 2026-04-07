# RailsGoat Command Injection
# Expected: GTSS-INJ-002, GTSS-RB-002
# CWE-78, OWASP A03
class ToolsController < ApplicationController

  # VULNERABLE: RailsGoat command injection via system()
  def ping
    ip = params[:ip]
    output = `ping -c 4 #{ip}`
    render plain: output
  end

  # VULNERABLE: RailsGoat command injection via system call
  def lookup
    host = params[:host]
    system("nslookup #{host}")
  end

  # VULNERABLE: exec with user input
  def execute
    command = params[:cmd]
    result = exec(command)
    render plain: result
  end
end
