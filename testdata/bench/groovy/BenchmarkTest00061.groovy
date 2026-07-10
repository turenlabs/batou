import java.io.*

def data = request.inputStream
def ois = new ObjectInputStream(data)
def obj = ois.readObject()
ois.close()
