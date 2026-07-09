import org.yaml.snakeyaml.Yaml

def url = params.config_url
def content = new URL(url).text
def yaml = new Yaml()
def config = yaml.load(content)
