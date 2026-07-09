package com.example.vulnerable

import com.mongodb.BasicDBObject
import com.mongodb.client.MongoCollection
import com.mongodb.client.MongoDatabase
import org.bson.BsonDocument
import org.springframework.data.mongodb.core.MongoTemplate

class MongoController {

    MongoCollection collection
    MongoDatabase database
    MongoTemplate mongoTemplate

    def findUser(params) {
        def filter = BasicDBObject.parse(params.filter)
        collection.find(filter)
    }

    def aggregateOrders(params) {
        def pipeline = params.pipeline
        collection.aggregate(pipeline)
    }

    def updateAccount(params) {
        def filter = params.filter
        collection.updateOne(filter, params.update)
    }

    def purgeRecords(params) {
        def filter = params.filter
        collection.deleteMany(filter)
    }

    def modifyDoc(params) {
        def filter = params.filter
        collection.findOneAndUpdate(filter, params.update)
    }

    def parseBsonFromUser(params) {
        def q = BsonDocument.parse(params.json)
    }

    def runAdminCmd(params) {
        def cmd = params.command
        database.runCommand(cmd)
    }

    def springFind(params) {
        def query = params.query
        mongoTemplate.find(query, User.class)
    }

    def springFindOne(params) {
        def query = params.query
        mongoTemplate.findOne(query, User.class)
    }
}
