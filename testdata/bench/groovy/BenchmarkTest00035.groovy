pipeline {
    agent { label 'windows' }
    stages {
        stage('Build') {
            steps {
                script {
                    def config = params.CONFIG
                    bat "msbuild /p:Configuration=${config}"
                }
            }
        }
    }
}
