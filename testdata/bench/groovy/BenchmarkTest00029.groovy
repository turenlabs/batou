pipeline {
    agent any
    stages {
        stage('Deploy') {
            steps {
                script {
                    def target = params.TARGET
                    sh "deploy.sh ${target}"
                }
            }
        }
    }
}
