package groovy

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// ==========================================================================
// GTSS-GVY-001: Command Injection
// ==========================================================================

func TestGVY001_GStringExecute(t *testing.T) {
	content := `def runCmd(String userInput) {
    "ls -la ${userInput}".execute()
}`
	result := testutil.ScanContent(t, "/app/CmdRunner.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-001")
}

func TestGVY001_ListExecute(t *testing.T) {
	content := `def runCmd(String dir) {
    ["ls", "-la", dir].execute()
}`
	result := testutil.ScanContent(t, "/app/CmdRunner.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-001")
}

func TestGVY001_RuntimeExec(t *testing.T) {
	content := `def runCmd(String cmd) {
    Runtime.getRuntime().exec(cmd)
}`
	result := testutil.ScanContent(t, "/app/CmdRunner.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-001")
}

func TestGVY001_ProcessBuilder(t *testing.T) {
	content := `def runCmd(String cmd) {
    def pb = new ProcessBuilder(cmd.split(" "))
    pb.start()
}`
	result := testutil.ScanContent(t, "/app/CmdRunner.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-001")
}

func TestGVY001_StaticCommand_Safe(t *testing.T) {
	content := `def listFiles() {
    def output = "ls -la /tmp".execute().text
    return output
}`
	result := testutil.ScanContent(t, "/app/CmdRunner.groovy", content)
	testutil.MustNotFindRule(t, result, "GTSS-GVY-001")
}

// ==========================================================================
// GTSS-GVY-002: Code Injection
// ==========================================================================

func TestGVY002_GroovyShellEvaluate(t *testing.T) {
	content := `def eval(String script) {
    new GroovyShell().evaluate(script)
}`
	result := testutil.ScanContent(t, "/app/ScriptRunner.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-002")
}

func TestGVY002_ShellEvaluate(t *testing.T) {
	content := `def eval(String script) {
    def shell = new GroovyShell()
    shell.evaluate(script)
}`
	result := testutil.ScanContent(t, "/app/ScriptRunner.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-002")
}

func TestGVY002_EvalMe(t *testing.T) {
	content := `def eval(String expr) {
    def result = Eval.me(expr)
    return result
}`
	result := testutil.ScanContent(t, "/app/ScriptRunner.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-002")
}

func TestGVY002_EvalX(t *testing.T) {
	content := `def eval(String expr, int x) {
    def result = Eval.x(x, expr)
    return result
}`
	result := testutil.ScanContent(t, "/app/ScriptRunner.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-002")
}

func TestGVY002_GroovyScriptEngine(t *testing.T) {
	content := `def run(String scriptName) {
    def engine = new GroovyScriptEngine("scripts/")
    engine.run(scriptName, new Binding())
}`
	result := testutil.ScanContent(t, "/app/ScriptRunner.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-002")
}

func TestGVY002_StaticScript_StillFlags(t *testing.T) {
	// Even static usage is flagged because evaluate() is inherently dangerous
	content := `def setup() {
    new GroovyShell().evaluate("println 'hello'")
}`
	result := testutil.ScanContent(t, "/app/ScriptRunner.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-002")
}

// ==========================================================================
// GTSS-GVY-003: SQL Injection
// ==========================================================================

func TestGVY003_SQLExecuteGString(t *testing.T) {
	content := `def deleteUser(Sql sql, String name) {
    sql.execute("DELETE FROM users WHERE name = '${name}'")
}`
	result := testutil.ScanContent(t, "/app/UserDao.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-003")
}

func TestGVY003_SQLRowsGString(t *testing.T) {
	content := `def findUser(Sql sql, String name) {
    sql.rows("SELECT * FROM users WHERE name = '${name}'")
}`
	result := testutil.ScanContent(t, "/app/UserDao.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-003")
}

func TestGVY003_SQLFirstRowGString(t *testing.T) {
	content := `def getUser(Sql sql, String id) {
    sql.firstRow("SELECT * FROM users WHERE id = ${id}")
}`
	result := testutil.ScanContent(t, "/app/UserDao.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-003")
}

func TestGVY003_SQLExecuteConcat(t *testing.T) {
	content := `def deleteUser(Sql sql, String name) {
    sql.execute("DELETE FROM users WHERE name = '" + name + "'")
}`
	result := testutil.ScanContent(t, "/app/UserDao.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-003")
}

func TestGVY003_SQLRowsConcat(t *testing.T) {
	content := `def findUser(Sql sql, String name) {
    sql.rows("SELECT * FROM users WHERE name = '" + name + "'")
}`
	result := testutil.ScanContent(t, "/app/UserDao.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-003")
}

func TestGVY003_SQLParameterized_Safe(t *testing.T) {
	content := `def findUser(Sql sql, String name) {
    sql.rows("SELECT * FROM users WHERE name = ?", [name])
}`
	result := testutil.ScanContent(t, "/app/UserDao.groovy", content)
	testutil.MustNotFindRule(t, result, "GTSS-GVY-003")
}

func TestGVY003_SQLExecuteUpdate_GString(t *testing.T) {
	content := `def updateUser(Sql sql, String name, int id) {
    sql.executeUpdate("UPDATE users SET name = '${name}' WHERE id = ${id}")
}`
	result := testutil.ScanContent(t, "/app/UserDao.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-003")
}

// ==========================================================================
// GTSS-GVY-004: Jenkins Pipeline Injection
// ==========================================================================

func TestGVY004_ShGString(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Build') {
            steps {
                sh "echo ${params.USER_INPUT}"
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-004")
}

func TestGVY004_ShScriptGString(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Deploy') {
            steps {
                sh(script: "deploy.sh ${params.BRANCH}")
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-004")
}

func TestGVY004_BatGString(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Build') {
            steps {
                bat "echo ${params.USER_INPUT}"
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-004")
}

func TestGVY004_LoadVariable(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Load') {
            steps {
                load ${env.SCRIPT_PATH}
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-004")
}

func TestGVY004_ShSingleQuote_Safe(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Build') {
            steps {
                sh 'echo $USER_INPUT'
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustNotFindRule(t, result, "GTSS-GVY-004")
}

// ==========================================================================
// GTSS-GVY-005: GString Injection
// ==========================================================================

func TestGVY005_GStringInLDAP(t *testing.T) {
	content := `def findUser(String username) {
    ldap.search("uid=${username},ou=users,dc=example,dc=com")
}`
	result := testutil.ScanContent(t, "/app/LdapService.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-005")
}

func TestGVY005_Parameterized_Safe(t *testing.T) {
	content := `def findUser(Sql sql, String name) {
    sql.rows("SELECT * FROM users WHERE name = ?", [name])
}`
	result := testutil.ScanContent(t, "/app/UserDao.groovy", content)
	testutil.MustNotFindRule(t, result, "GTSS-GVY-005")
}

// ==========================================================================
// GTSS-GVY-006: Grails Mass Assignment
// ==========================================================================

func TestGVY006_NewDomainWithParams(t *testing.T) {
	content := `class UserController {
    def save() {
        def user = new User(params)
        user.save()
    }
}`
	result := testutil.ScanContent(t, "/app/UserController.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-006")
}

func TestGVY006_PropertiesFromParams(t *testing.T) {
	content := `class UserController {
    def update() {
        def user = User.get(params.id)
        user.properties = params
        user.save()
    }
}`
	result := testutil.ScanContent(t, "/app/UserController.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-006")
}

func TestGVY006_BindDataWithoutFilter(t *testing.T) {
	content := `class UserController {
    def update() {
        def user = User.get(params.id)
        bindData(user, params)
        user.save()
    }
}`
	result := testutil.ScanContent(t, "/app/UserController.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-006")
}

func TestGVY006_BindDataWithFilter_Safe(t *testing.T) {
	content := `class UserController {
    def update() {
        def user = User.get(params.id)
        bindData(user, params, [include: ['name', 'email']])
        user.save()
    }
}`
	result := testutil.ScanContent(t, "/app/UserController.groovy", content)
	testutil.MustNotFindRule(t, result, "GTSS-GVY-006")
}

func TestGVY006_CommandObject_Safe(t *testing.T) {
	content := `@Validateable
class UserCommand {
    String name
    String email
}

class UserController {
    def save(UserCommand cmd) {
        if (cmd.validate()) {
            def user = new User(name: cmd.name, email: cmd.email)
            user.save()
        }
    }
}`
	result := testutil.ScanContent(t, "/app/UserController.groovy", content)
	testutil.MustNotFindRule(t, result, "GTSS-GVY-006")
}

// ==========================================================================
// GTSS-GVY-007: XXE via XmlSlurper/XmlParser
// ==========================================================================

func TestGVY007_XmlSlurperDefault(t *testing.T) {
	content := `def parseXml(String xml) {
    def root = new XmlSlurper().parseText(xml)
    return root.name()
}`
	result := testutil.ScanContent(t, "/app/XmlService.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-007")
}

func TestGVY007_XmlParserDefault(t *testing.T) {
	content := `def parseXml(String xml) {
    def root = new XmlParser().parseText(xml)
    return root.name()
}`
	result := testutil.ScanContent(t, "/app/XmlService.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-007")
}

func TestGVY007_XmlSlurperSecure_Safe(t *testing.T) {
	content := `def parseXml(String xml) {
    def slurper = new XmlSlurper()
    slurper.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    def root = slurper.parseText(xml)
    return root.name()
}`
	result := testutil.ScanContent(t, "/app/XmlService.groovy", content)
	testutil.MustNotFindRule(t, result, "GTSS-GVY-007")
}

// ==========================================================================
// GTSS-GVY-008: Insecure Deserialization
// ==========================================================================

func TestGVY008_ObjectInputStream(t *testing.T) {
	content := `def deserialize(InputStream input) {
    def ois = new ObjectInputStream(input)
    return ois.readObject()
}`
	result := testutil.ScanContent(t, "/app/Serializer.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-008")
}

func TestGVY008_XStream(t *testing.T) {
	content := `def deserialize(String xml) {
    def xstream = new XStream()
    return xstream.fromXML(xml)
}`
	result := testutil.ScanContent(t, "/app/Serializer.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-008")
}

func TestGVY008_SnakeYAML(t *testing.T) {
	content := `def loadConfig(String yamlStr) {
    def yaml = new Yaml()
    return yaml.load(yamlStr)
}`
	result := testutil.ScanContent(t, "/app/ConfigLoader.groovy", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-008")
}

func TestGVY008_SnakeYAMLSafe_Safe(t *testing.T) {
	content := `def loadConfig(String yamlStr) {
    def yaml = new Yaml(new SafeConstructor())
    return yaml.load(yamlStr)
}`
	result := testutil.ScanContent(t, "/app/ConfigLoader.groovy", content)
	testutil.MustNotFindRule(t, result, "GTSS-GVY-008")
}

// ==========================================================================
// GTSS-GVY-009: Jenkins Credentials Leak
// ==========================================================================

func TestGVY009_CredentialInSh(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Deploy') {
            steps {
                withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {
                    sh "curl -H 'Authorization: Bearer ${TOKEN}'"
                }
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-009")
}

func TestGVY009_CredentialInEcho(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Debug') {
            steps {
                withCredentials([string(credentialsId: 'secret', variable: 'SECRET')]) {
                    echo "The secret is ${SECRET}"
                }
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-009")
}

func TestGVY009_CredentialSingleQuote_Safe(t *testing.T) {
	content := `pipeline {
    stages {
        stage('Deploy') {
            steps {
                withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {
                    sh 'curl -H "Authorization: Bearer $TOKEN"'
                }
            }
        }
    }
}`
	result := testutil.ScanContent(t, "/app/Jenkinsfile", content)
	testutil.MustNotFindRule(t, result, "GTSS-GVY-009")
}

// ==========================================================================
// GTSS-GVY-010: Grails XSS
// ==========================================================================

func TestGVY010_GspRawOutput(t *testing.T) {
	content := `<!DOCTYPE html>
<html>
<body>
    <h1>Welcome</h1>
    <div>${user.name}</div>
</body>
</html>`
	result := testutil.ScanContent(t, "/app/views/user/show.gsp", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-010")
}

func TestGVY010_RawMethod(t *testing.T) {
	content := `<!DOCTYPE html>
<html>
<body>
    <div>${raw(user.bio)}</div>
</body>
</html>`
	result := testutil.ScanContent(t, "/app/views/user/show.gsp", content)
	testutil.MustFindRule(t, result, "GTSS-GVY-010")
}

func TestGVY010_EncodeAsHTML_Safe(t *testing.T) {
	content := `<!DOCTYPE html>
<html>
<body>
    <div>${user.name.encodeAsHTML()}</div>
</body>
</html>`
	result := testutil.ScanContent(t, "/app/views/user/show.gsp", content)
	testutil.MustNotFindRule(t, result, "GTSS-GVY-010")
}

func TestGVY010_DefaultCodecHTML_Safe(t *testing.T) {
	content := `<%@ defaultCodec="HTML" %>
<!DOCTYPE html>
<html>
<body>
    <div>${user.name}</div>
</body>
</html>`
	result := testutil.ScanContent(t, "/app/views/user/show.gsp", content)
	testutil.MustNotFindRule(t, result, "GTSS-GVY-010")
}

func TestGVY010_NonGSP_Safe(t *testing.T) {
	content := `class UserService {
    def name = "${user.name}"
    println name
}`
	result := testutil.ScanContent(t, "/app/UserService.groovy", content)
	testutil.MustNotFindRule(t, result, "GTSS-GVY-010")
}
