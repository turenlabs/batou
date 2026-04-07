# Vulnerable: Command injection via system() and backticks with interpolation
# Expected: GTSS-INJ-002 (Command Injection)

class FileController < ApplicationController
  def download
    filename = params[:file]
    system("cp /uploads/#{filename} /tmp/download")
    send_file "/tmp/download"
  end

  def convert
    input_path = params[:path]
    output = `convert #{input_path} -resize 100x100 /tmp/thumb.png`
    render plain: output
  end

  def compress
    dir = params[:directory]
    system("tar -czf /tmp/archive.tar.gz #{dir}")
    send_file "/tmp/archive.tar.gz"
  end

  def ping
    host = params[:host]
    result = `ping -c 3 #{host}`
    render plain: result
  end
end
