// Safe: Jenkins pipeline with single-quoted strings (no GString interpolation)
pipeline {
    agent any
    parameters {
        string(name: 'BRANCH', defaultValue: 'main')
    }
    stages {
        stage('Build') {
            steps {
                sh 'git checkout $BRANCH'
                sh 'make build'
                bat 'run-tests.bat'
            }
        }
        stage('Deploy') {
            steps {
                httpRequest(url: 'https://internal.example.com/api/health')
                writeFile(file: 'output.txt', text: 'build complete')
            }
        }
    }
}
