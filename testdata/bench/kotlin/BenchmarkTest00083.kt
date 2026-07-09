package bench

import javax.servlet.http.HttpServletRequest
import java.io.ObjectInputStream

// Vulnerable: ObjectInputStream from servlet input stream
fun handler00083(request: HttpServletRequest): Any {
    val ois = ObjectInputStream(request.inputStream)
    return ois.readObject()
}
