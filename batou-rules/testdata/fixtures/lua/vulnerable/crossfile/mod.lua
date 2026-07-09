-- Required module that returns request-controlled data (OpenResty).
-- The taint SOURCE (ngx.var.arg_id) lives here; the SINK is in app.lua.
local M = {}

function M.get_id()
  return ngx.var.arg_id
end

return M
