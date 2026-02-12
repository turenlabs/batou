from graphene import Schema, ObjectType, String, Field


# SAFE: GraphQL query using parameterized variables
def search_user(username: str):
    query = "query GetUser($name: String!) { user(name: $name) { id email role } }"
    result = schema.execute(query, variables={"name": username})
    return result.data


# SAFE: Static query string with no user input interpolation
def list_users():
    query = "query { users { id email } }"
    result = schema.execute(query)
    return result.data
