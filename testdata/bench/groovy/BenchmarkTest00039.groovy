node {
    def url = params.WEBHOOK_URL
    sh "curl -X POST ${url}"
}
