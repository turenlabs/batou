import com.thoughtworks.xstream.XStream

def xml = request.getParameter("data")
def xstream = new XStream()
def obj = xstream.fromXML(xml)
