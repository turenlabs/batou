// Vulnerable: Jenkins pipeline steps with tainted build parameters
pipeline {
    agent any
    parameters {
        string(name: 'REPO_URL', defaultValue: '')
        string(name: 'SCRIPT_PATH', defaultValue: '')
        string(name: 'TARGET_URL', defaultValue: '')
        string(name: 'OUTPUT_FILE', defaultValue: '')
        string(name: 'RECIPIENT', defaultValue: '')
    }
    stages {
        stage('Command Injection via sh') {
            steps {
                sh "git clone ${params.REPO_URL}"
                bat "deploy.bat ${params.REPO_URL}"
            }
        }
        stage('SSRF via httpRequest') {
            steps {
                httpRequest(url: "${params.TARGET_URL}/api/health")
            }
        }
        stage('Path Traversal via writeFile') {
            steps {
                writeFile(file: "${params.OUTPUT_FILE}", text: 'data')
            }
        }
        stage('Code Injection via load') {
            steps {
                load "${params.SCRIPT_PATH}"
            }
        }
        stage('SSRF via checkout') {
            steps {
                checkout([$class: 'GitSCM', userRemoteConfigs: [[url: "${params.REPO_URL}"]]])
            }
        }
        stage('HTML Injection via emailext') {
            steps {
                emailext(body: "${params.RECIPIENT} submitted a build", to: "${params.RECIPIENT}")
            }
        }
    }
}
