// Vulnerable: Grails mass assignment via direct params binding
class UserController {
    def save() {
        def user = new User(params)
        user.save()
    }

    def update() {
        def user = User.get(params.id)
        user.properties = params
        user.save()
    }

    def updateBind() {
        def user = User.get(params.id)
        bindData(user, params)
        user.save()
    }
}
