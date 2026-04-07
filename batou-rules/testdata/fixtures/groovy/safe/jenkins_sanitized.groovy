// Safe: Jenkins pipeline with sanitized inputs
pipeline {
    agent any
    parameters {
        string(name: 'BRANCH', defaultValue: 'main')
        string(name: 'COUNT', defaultValue: '10')
    }
    stages {
        stage('Safe Integer Conversion') {
            steps {
                def count = params.COUNT.toInteger()
                sh "echo Processing ${count} items"
            }
        }
        stage('Safe Allowlisted Branch') {
            steps {
                def branch = params.BRANCH
                if (branch.matches('^[a-zA-Z0-9_/.-]+$')) {
                    sh "git checkout ${branch}"
                }
            }
        }
    }
}
