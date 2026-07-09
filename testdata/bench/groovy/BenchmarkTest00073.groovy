import java.io.*

class DataController {
    def load() {
        def file = params.file
        def fis = new FileInputStream(file)
        def ois = new ObjectInputStream(fis)
        def obj = ois.readObject()
        ois.close()
        render obj.toString()
    }
}
