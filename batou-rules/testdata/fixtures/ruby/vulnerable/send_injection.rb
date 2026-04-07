# GTSS-RB-006: send/public_send with user input

class DynamicDispatcher
  def dispatch
    # Vulnerable: send with user-controlled method name
    obj.send(params[:method], params[:arg])
  end

  def call_action
    # Vulnerable: public_send with params
    record.public_send(params[:action])
  end
end
