-- Importer: requires mod.lua and forwards its tainted return into a SQL
-- sink. Cross-file (Layer-4) taint: source in mod.lua -> require -> sink
-- here. Expected finding: BATOU-INTERPROC-SQL_QUERY (CWE-89) at the
-- db:query line.
local m = require("mod")

local function handle(db)
  -- inlined tainted return reaches the SQL sink
  db:query(m.get_id())
end

return handle
