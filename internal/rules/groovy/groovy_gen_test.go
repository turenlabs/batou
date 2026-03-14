package groovy

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// ==========================================================================
// BATOU-GVY-017: Jenkins File Path Traversal
// ==========================================================================

func TestGVY017_ReadFileWithParams(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Read') {
            steps {
                def data = readFile(file: "${params.FILE_PATH}")
                echo data
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-017")
}

func TestGVY017_WriteFileWithInput(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Write') {
            steps {
                writeFile(file: "${input.filename}", text: 'data')
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-017")
}

func TestGVY017_ReadFileWithEnv(t *testing.T) {
	content := `def data = readFile(file: "${env.USER_FILE}")`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-017")
}

func TestGVY017_StaticPath_Safe(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Read') {
            steps {
                def data = readFile(file: 'config.yaml')
                echo data
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustNotFindRule(t, result, "BATOU-GVY-017")
}

// ==========================================================================
// BATOU-GVY-018: @Grab Dependency Injection
// ==========================================================================

func TestGVY018_GrabAnnotation(t *testing.T) {
	content := `@Grab(group='org.apache.commons', module='commons-lang3', version='3.12.0')
import org.apache.commons.lang3.StringUtils

println StringUtils.capitalize("hello")`
	result := testutil.ScanContent(t, "/app/Script.groovy", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-018")
}

func TestGVY018_GrabShortForm(t *testing.T) {
	content := `@Grab('org.codehaus.groovy:groovy-all:3.0.9')
def process(data) { return data }`
	result := testutil.ScanContent(t, "/app/Script.groovy", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-018")
}

func TestGVY018_NoGrab_Safe(t *testing.T) {
	content := `import org.apache.commons.lang3.StringUtils

class MyService {
    String capitalize(String input) {
        return StringUtils.capitalize(input)
    }
}`
	result := testutil.ScanContent(t, "/app/MyService.groovy", content)
	testutil.MustNotFindRule(t, result, "BATOU-GVY-018")
}

// ==========================================================================
// BATOU-GVY-019: Jenkins Load Step Injection
// ==========================================================================

func TestGVY019_LoadWithInterpolation(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Load') {
            steps {
                load "${env.SCRIPT_DIR}/setup.groovy"
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-019")
}

func TestGVY019_LoadWithParamInterp(t *testing.T) {
	content := `def script = load "${params.SCRIPT_NAME}"`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-019")
}

func TestGVY019_StaticLoad_Safe(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Load') {
            steps {
                load "shared/setup.groovy"
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustNotFindRule(t, result, "BATOU-GVY-019")
}

// ==========================================================================
// BATOU-GVY-020: Grails Render Text XSS
// ==========================================================================

func TestGVY020_RenderTextWithParams(t *testing.T) {
	content := `class UserController {
    def show() {
        render text: "Hello, " + params.name
    }
}`
	result := testutil.ScanContent(t, "/app/UserController.groovy", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-020")
}

func TestGVY020_RenderTextWithRequest(t *testing.T) {
	content := `class ApiController {
    def echo() {
        render text: request.getParameter("msg")
    }
}`
	result := testutil.ScanContent(t, "/app/ApiController.groovy", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-020")
}

func TestGVY020_RenderView_Safe(t *testing.T) {
	content := `class UserController {
    def show() {
        render view: "show", model: [user: User.get(params.id)]
    }
}`
	result := testutil.ScanContent(t, "/app/UserController.groovy", content)
	testutil.MustNotFindRule(t, result, "BATOU-GVY-020")
}

// ==========================================================================
// BATOU-GVY-021: Spring @Value SpEL Injection
// ==========================================================================

func TestGVY021_ValueWithNestedSpEL(t *testing.T) {
	content := `import org.springframework.beans.factory.annotation.Value

class AppConfig {
    @Value("${app.admin.role:#{defaultRole}}")
    String adminRole
}`
	result := testutil.ScanContent(t, "/app/AppConfig.groovy", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-021")
}

func TestGVY021_ValueSimpleProperty_Safe(t *testing.T) {
	content := `import org.springframework.beans.factory.annotation.Value

class AppConfig {
    @Value("${app.name}")
    String appName
}`
	result := testutil.ScanContent(t, "/app/AppConfig.groovy", content)
	testutil.MustNotFindRule(t, result, "BATOU-GVY-021")
}

func TestGVY021_ValuePureSpEL_Safe(t *testing.T) {
	content := `import org.springframework.beans.factory.annotation.Value

class AppConfig {
    @Value("#{systemProperties['app.name']}")
    String appName
}`
	result := testutil.ScanContent(t, "/app/AppConfig.groovy", content)
	testutil.MustNotFindRule(t, result, "BATOU-GVY-021")
}

// ==========================================================================
// BATOU-GVY-022: JsonSlurper on Untrusted URL
// ==========================================================================

func TestGVY022_JsonSlurperParseURL(t *testing.T) {
	content := `def fetchData(String url) {
    def data = new JsonSlurper().parse(new URL(url))
    return data
}`
	result := testutil.ScanContent(t, "/app/DataFetcher.groovy", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-022")
}

func TestGVY022_JsonSlurperParseHttpUrl(t *testing.T) {
	content := `def fetchConfig() {
    def json = new JsonSlurper().parse(httpUrl.toURL())
    return json
}`
	result := testutil.ScanContent(t, "/app/ConfigLoader.groovy", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-022")
}

func TestGVY022_JsonSlurperParseText_Safe(t *testing.T) {
	content := `def parseJson(String text) {
    def data = new JsonSlurper().parseText(text)
    return data
}`
	result := testutil.ScanContent(t, "/app/DataParser.groovy", content)
	testutil.MustNotFindRule(t, result, "BATOU-GVY-022")
}

// ==========================================================================
// BATOU-GVY-023: Jenkins httpRequest SSRF
// ==========================================================================

func TestGVY023_HttpRequestWithParams(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Call API') {
            steps {
                def response = httpRequest "https://api.example.com/${params.ENDPOINT}"
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-023")
}

func TestGVY023_HttpRequestWithEnv(t *testing.T) {
	content := `def resp = httpRequest url: "https://${env.TARGET_HOST}/api/health"`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-023")
}

func TestGVY023_HttpRequestWithInput(t *testing.T) {
	content := `def resp = httpRequest "https://internal.svc/${input.url}"`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-023")
}

func TestGVY023_HttpRequestStaticURL_Safe(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Health Check') {
            steps {
                def response = httpRequest 'https://api.example.com/health'
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustNotFindRule(t, result, "BATOU-GVY-023")
}

// ==========================================================================
// BATOU-GVY-024: GORM executeUpdate Injection
// ==========================================================================

func TestGVY024_ExecuteUpdateGString(t *testing.T) {
	content := `class UserService {
    void deactivateUser(String username) {
        User.executeUpdate("UPDATE User SET active = false WHERE username = ${username}")
    }
}`
	result := testutil.ScanContent(t, "/app/UserService.groovy", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-024")
}

func TestGVY024_ExecuteUpdateIdInterp(t *testing.T) {
	content := `def deleteOldRecords(long userId) {
    AuditLog.executeUpdate("DELETE FROM AuditLog WHERE userId = ${userId}")
}`
	result := testutil.ScanContent(t, "/app/AuditService.groovy", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-024")
}

func TestGVY024_ExecuteUpdateParameterized_Safe(t *testing.T) {
	content := `class UserService {
    void deactivateUser(String username) {
        User.executeUpdate("UPDATE User SET active = false WHERE username = ?", [username])
    }
}`
	result := testutil.ScanContent(t, "/app/UserService.groovy", content)
	testutil.MustNotFindRule(t, result, "BATOU-GVY-024")
}

// ==========================================================================
// BATOU-GVY-025: Pipeline Input Without Timeout
// ==========================================================================

func TestGVY025_InputNoTimeout(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Approval') {
            steps {
                input message: 'Deploy to production?'
                sh 'deploy.sh'
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-025")
}

func TestGVY025_InputIdNoTimeout(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Gate') {
            steps {
                input id: 'deploy-gate', message: 'Proceed?'
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-025")
}

func TestGVY025_InputWithTimeout_Safe(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Approval') {
            steps {
                timeout(time: 1, unit: 'HOURS') {
                    input message: 'Deploy to production?'
                }
                sh 'deploy.sh'
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustNotFindRule(t, result, "BATOU-GVY-025")
}

// ==========================================================================
// BATOU-GVY-026: @NonCPS with Security Operations
// ==========================================================================

func TestGVY026_NonCPSWithFile(t *testing.T) {
	content := `@NonCPS
def readSecret() {
    def f = new File("/etc/secrets/token")
    return f.text
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-026")
}

func TestGVY026_NonCPSWithRuntimeExec(t *testing.T) {
	content := `@NonCPS
def runCommand(String cmd) {
    return Runtime.exec(cmd)
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-026")
}

func TestGVY026_NonCPSWithProcessBuilder(t *testing.T) {
	content := `@NonCPS
def execute(List args) {
    def pb = new ProcessBuilder(args)
    return pb.start()
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-026")
}

func TestGVY026_NonCPSWithURL(t *testing.T) {
	content := `@NonCPS
def fetch(String endpoint) {
    def conn = new URL(endpoint).openConnection()
    return conn.inputStream.text
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "BATOU-GVY-026")
}

func TestGVY026_NonCPSSafeOps_Safe(t *testing.T) {
	content := `@NonCPS
def parseJson(String text) {
    def slurper = new groovy.json.JsonSlurper()
    return slurper.parseText(text)
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustNotFindRule(t, result, "BATOU-GVY-026")
}

func TestGVY026_RegularMethodWithFile_Safe(t *testing.T) {
	content := `def readConfig() {
    def f = new File("/etc/config.yaml")
    return f.text
}`
	result := testutil.ScanContent(t, "/app/Pipeline.groovy", content)
	testutil.MustNotFindRule(t, result, "BATOU-GVY-026")
}
