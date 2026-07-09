import Vapor
import Foundation

struct Event: Content { var title: String; var date: Date }

func handler099(_ req: Request) throws -> String {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    let event = try decoder.decode(Event.self, from: req.body.data ?? Data())
    return event.title
}
