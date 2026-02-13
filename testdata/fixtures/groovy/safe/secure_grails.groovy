// Safe: Grails controller with command objects and filtered binding
import grails.validation.Validateable

@Validateable
class UserCommand {
    String name
    String email

    static constraints = {
        name blank: false, maxSize: 100
        email email: true
    }
}

class UserController {
    def save(UserCommand cmd) {
        if (cmd.validate()) {
            def user = new User(name: cmd.name, email: cmd.email)
            user.save()
        }
    }

    def update() {
        def user = User.get(params.id)
        bindData(user, params, [include: ['name', 'email']])
        user.save()
    }
}
