# VULNERABLE: Rails controller stashes request data on an instance variable
# and an attribute setter, then feeds both into system() — CWE-78.
# Exercises tsflow @ivar and obj.attr= LHS field-sensitive taint tracking.
class HomeController < ApplicationController
  def index
    @q = params[:q]
    system(@q)
  end

  def ping
    @host = params[:host]
    system("ping -c 1 #{@host}")
  end

  def run
    job = Job.new
    job.cmd = params[:cmd]
    system(job.cmd)
  end
end
