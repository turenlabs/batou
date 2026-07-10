def call(Map config) {
    def code = config.customScript
    def shell = new GroovyShell()
    shell.evaluate(code)
}
