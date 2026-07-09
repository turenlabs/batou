import groovy.json.JsonSlurper
import java.net.*

def server = new ServerSocket(9090)
def client = server.accept()
def reader = new BufferedReader(new InputStreamReader(client.inputStream))
def json = reader.readLine()
def message = new JsonSlurper().parseText(json)
