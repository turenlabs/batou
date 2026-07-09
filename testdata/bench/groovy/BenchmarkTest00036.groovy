pipeline {
    agent { label 'windows' }
    stages {
        stage('Build') {
            steps {
                bat 'msbuild /p:Configuration=Release'
            }
        }
    }
}
