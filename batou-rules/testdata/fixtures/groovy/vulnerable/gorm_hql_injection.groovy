// Vulnerable: Grails GORM HQL injection via GString interpolation
import grails.gorm.transactions.Transactional

@Transactional
class UserService {

    def findByName(String name) {
        User.executeQuery("from User where name = '${name}'")
    }

    def findSingle(String email) {
        User.find("from User where email = '${email}'")
    }

    def findMultiple(String role) {
        User.findAll("from User where role = '${role}'")
    }

    def deleteByName(String name) {
        User.executeUpdate("delete from User where name = '${name}'")
    }

    def searchWithCriteria(String input) {
        User.withCriteria {
            sqlRestriction("username = '${input}'")
        }
    }
}
