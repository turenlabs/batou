import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

class ConfigController {
    def upload() {
        def content = params.yaml_content
        def yaml = new Yaml(new SafeConstructor())
        def config = yaml.load(content)
        render config as JSON
    }
}
