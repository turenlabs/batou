# RailsGoat XSS
# Expected: GTSS-RB-001, GTSS-FW-RAILS-001
# CWE-79, OWASP A03
class MessagesController < ApplicationController

  # VULNERABLE: RailsGoat XSS via raw output in template helper
  def show
    @message = Message.find(params[:id])
    # In the view: <%= raw @message.body %>
    # Simulated here:
    @output = @message.body.html_safe
  end

  # VULNERABLE: RailsGoat XSS via render inline with user data
  def preview
    content = params[:content]
    render inline: "<div>#{content}</div>"
  end

  # VULNERABLE: Using html_safe on user input
  def display
    @comment = params[:comment].html_safe
    render plain: @comment
  end
end
