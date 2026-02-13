// Safe: Jenkins pipeline with single-quoted strings and proper credential handling
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
            }
        }
        stage('Deploy') {
            steps {
                withCredentials([string(credentialsId: 'deploy-token', variable: 'TOKEN')]) {
                    sh 'curl -H "Authorization: Bearer $TOKEN" https://deploy.example.com'
                }
            }
        }
    }
}
