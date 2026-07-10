def host = params.host
"ping -c 4 ${host}".execute()
