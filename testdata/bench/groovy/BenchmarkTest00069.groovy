import com.thoughtworks.xstream.XStream

class ImportController {
    def importData() {
        def body = request.reader.text
        def xstream = new XStream()
        def data = xstream.fromXML(body)
        render "Imported ${data.size()} records"
    }
}
