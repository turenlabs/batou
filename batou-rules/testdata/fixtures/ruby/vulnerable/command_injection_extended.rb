# Extended command injection vulnerabilities
# Tests: Open3.capture3, Open3.popen3, Open3.pipeline, Process.spawn, PTY.spawn

require 'open3'
require 'pty'

class ToolController < ApplicationController
  def run_tool
    cmd = params[:command]
    # Vulnerable: Open3.capture3 with tainted command
    stdout, stderr, status = Open3.capture3(cmd)
    render plain: stdout
  end

  def stream_output
    cmd = params[:command]
    # Vulnerable: Open3.popen3 with tainted command
    Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
      render plain: stdout.read
    end
  end

  def pipeline_exec
    cmd = params[:command]
    # Vulnerable: Open3.pipeline with tainted command
    Open3.pipeline(cmd)
  end

  def spawn_process
    cmd = params[:command]
    # Vulnerable: Process.spawn with tainted command
    pid = Process.spawn(cmd)
    Process.wait(pid)
    render plain: "done"
  end

  def terminal_exec
    cmd = params[:command]
    # Vulnerable: PTY.spawn with tainted command
    PTY.spawn(cmd) do |r, w, pid|
      output = r.read
      render plain: output
    end
  end
end
