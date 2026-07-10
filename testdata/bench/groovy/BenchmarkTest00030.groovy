pipeline {
    agent any
    stages {
        stage('Deploy') {
            steps {
                sh 'deploy.sh production'
            }
        }
    }
}
