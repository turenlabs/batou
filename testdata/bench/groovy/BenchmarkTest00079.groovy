import java.io.*

class SessionController {
    def restore() {
        def encoded = params.session_data
        def bytes = encoded.decodeBase64()
        def ois = new ObjectInputStream(new ByteArrayInputStream(bytes))
        def session = ois.readObject()
        render session.toString()
    }
}
