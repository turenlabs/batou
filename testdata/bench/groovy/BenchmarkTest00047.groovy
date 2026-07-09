class PluginController {
    def load() {
        def script = params.script
        def shell = new GroovyShell()
        def parsed = shell.parse(script)
        parsed.run()
    }
}
