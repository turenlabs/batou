// Vulnerable: Jenkins pipeline injection via GString in sh/bat steps
pipeline {
    agent any
    parameters {
        string(name: 'BRANCH', defaultValue: 'main')
        string(name: 'DEPLOY_TARGET', defaultValue: 'staging')
    }
    stages {
        stage('Build') {
            steps {
                sh "git checkout ${params.BRANCH}"
                sh "make build TARGET=${params.DEPLOY_TARGET}"
            }
        }
        stage('Test') {
            steps {
                bat "run-tests.bat ${params.BRANCH}"
            }
        }
        stage('Deploy') {
            steps {
                withCredentials([string(credentialsId: 'deploy-token', variable: 'TOKEN')]) {
                    sh "curl -H 'Authorization: Bearer ${TOKEN}' https://deploy.example.com"
                    echo "Deploying with token ${TOKEN}"
                }
            }
        }
        stage('Load Script') {
            steps {
                load ${env.SCRIPT_PATH}
            }
        }
    }
}
