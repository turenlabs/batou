// Vulnerable: Jenkins pipeline taint flows — user params to dangerous sinks
pipeline {
    agent any
    parameters {
        string(name: 'TARGET_HOST', defaultValue: 'localhost')
        string(name: 'SCRIPT_PATH', defaultValue: 'deploy.groovy')
        string(name: 'OUTPUT_FILE', defaultValue: 'report.txt')
    }
    stages {
        stage('SSRF via httpRequest') {
            steps {
                def resp = httpRequest(url: "http://${params.TARGET_HOST}/api/health")
                echo resp.content
            }
        }
        stage('Command Injection via sh') {
            steps {
                sh "curl http://${params.TARGET_HOST}/deploy"
                bat "ping ${params.TARGET_HOST}"
                powershell "Test-Connection ${params.TARGET_HOST}"
            }
        }
        stage('Path Traversal via writeFile/readFile') {
            steps {
                writeFile(file: "${params.OUTPUT_FILE}", text: 'report data')
                def content = readFile(file: "${params.SCRIPT_PATH}")
                echo content
            }
        }
        stage('Code Injection via load') {
            steps {
                load "${params.SCRIPT_PATH}"
            }
        }
    }
}
