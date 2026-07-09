def domain = request.getParameter("domain")
"nslookup ${domain}".execute()
