package com.example.safe

import com.mongodb.BasicDBObject
import com.mongodb.client.MongoCollection
import com.mongodb.client.model.Filters
import org.springframework.data.mongodb.core.MongoTemplate
import org.springframework.data.mongodb.core.query.Criteria
import org.springframework.data.mongodb.core.query.Query

// Shows the canonical safe patterns for MongoDB queries from Groovy.
// These use typed query builders (Filters, Criteria) with constant keys
// and validated / hard-coded values — no user-controlled data flows into
// the raw query/filter/pipeline document.
class SafeMongoController {

    MongoCollection collection
    MongoTemplate mongoTemplate

    def findActiveUsers() {
        def filter = Filters.eq("status", "active")
        collection.find(filter)
    }

    def countAdmins() {
        def filter = Filters.eq("role", "admin")
        collection.countDocuments(filter)
    }

    def updateLastSeen() {
        def filter = Filters.eq("role", "admin")
        def update = new BasicDBObject("\$set", new BasicDBObject("lastSeen", new Date()))
        collection.updateOne(filter, update)
    }

    def springFindActive() {
        def query = Query.query(Criteria.where("status").is("active"))
        mongoTemplate.find(query, User.class)
    }
}
