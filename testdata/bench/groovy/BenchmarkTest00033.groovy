def filename = request.getParameter("file")
"cat /var/data/${filename}".execute()
