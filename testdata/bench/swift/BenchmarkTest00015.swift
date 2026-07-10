import Vapor
import CoreData

func handler015(_ req: Request) throws -> String {
    let filter: String = try req.query.get(at: "filter")
    let predicate = NSPredicate(format: "name == %@", filter)
    let request = NSFetchRequest<NSManagedObject>(entityName: "User")
    request.predicate = predicate
    return "filtered"
}
