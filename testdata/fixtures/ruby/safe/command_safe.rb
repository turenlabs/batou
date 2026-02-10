# Safe: Command execution with array form (no shell interpolation)
# Expected: No findings for GTSS-INJ-002

require 'open3'

class FileController < ApplicationController
  def convert
    input_path = params[:path]
    # Safe: Open3.capture3 with array arguments prevents shell injection
    stdout, stderr, status = Open3.capture3("convert", input_path, "-resize", "100x100", "/tmp/thumb.png")
    if status.success?
      send_file "/tmp/thumb.png"
    else
      render plain: "Conversion failed", status: 500
    end
  end

  def list_files
    directory = params[:dir]
    # Safe: Array form of system() call
    stdout, stderr, status = Open3.capture3("ls", "-la", directory)
    render plain: stdout
  end

  def safe_ping
    host = params[:host]
    # Validate input before use
    unless host.match?(/\A[\w.\-]+\z/)
      render plain: "Invalid host", status: 400
      return
    end
    stdout, stderr, status = Open3.capture3("ping", "-c", "3", host)
    render plain: stdout
  end
end
