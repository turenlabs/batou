node {
    withCredentials([string(credentialsId: 'webhook', variable: 'URL')]) {
        sh 'curl -X POST $URL'
    }
}
