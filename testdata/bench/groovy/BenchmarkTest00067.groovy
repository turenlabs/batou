import java.io.*
import java.net.*

def server = new ServerSocket(9090)
def client = server.accept()
def ois = new ObjectInputStream(client.inputStream)
def message = ois.readObject()
