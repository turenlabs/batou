node {
    def version = params.VERSION
    "docker build -t myapp:${version} .".execute()
}
