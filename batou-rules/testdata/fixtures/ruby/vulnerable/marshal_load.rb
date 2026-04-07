# GTSS-RB-009: Unsafe Marshal.load

def restore_from_cache(blob)
  # Vulnerable: Marshal.load with untrusted data
  obj = Marshal.load(blob)
  process(obj)
end

def restore_session(data)
  # Vulnerable: Marshal.restore is alias for load
  session = Marshal.restore(data)
  session
end
