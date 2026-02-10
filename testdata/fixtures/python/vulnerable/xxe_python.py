# Vulnerable: XXE via lxml/ElementTree without safe parsing
# Expected: Taint sink match for py.xml.etree.parse (CWE-611)

from lxml import etree
import xml.etree.ElementTree as ET
from flask import Flask, request

app = Flask(__name__)


@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    xml_data = request.data
    parser = etree.XMLParser(resolve_entities=True)
    doc = etree.fromstring(xml_data, parser=parser)
    return etree.tostring(doc).decode()


@app.route("/import-xml", methods=["POST"])
def import_xml():
    xml_content = request.data.decode("utf-8")
    root = ET.fromstring(xml_content)
    items = []
    for item in root.findall("item"):
        items.append(item.text)
    return {"items": items}


@app.route("/process-svg", methods=["POST"])
def process_svg():
    svg_data = request.files["svg"].read()
    tree = ET.parse(svg_data)
    root = tree.getroot()
    return {"tag": root.tag}


@app.route("/soap", methods=["POST"])
def soap_endpoint():
    xml_body = request.get_data()
    parser = etree.XMLParser(
        no_network=False,
        resolve_entities=True,
        dtd_validation=False,
    )
    doc = etree.fromstring(xml_body, parser)
    return etree.tostring(doc).decode()
