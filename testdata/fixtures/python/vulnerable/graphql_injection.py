from graphene import Schema, ObjectType, String, Field
import requests


# VULNERABLE: GraphQL query built with f-string
def search_user(username: str):
    query = f"query {{ user(name: \"{username}\") {{ id email role }} }}"
    result = schema.execute(query)
    return result.data


# VULNERABLE: GraphQL query built with .format()
def get_user_by_id(user_id: str):
    query = "query {{ user(id: \"{}\") {{ id email role }} }}".format(user_id)
    result = schema.execute(query)
    return result.data


# VULNERABLE: GraphQL query built with % formatting
def delete_user(user_id: str):
    query = "mutation { deleteUser(id: \"%s\") { success } }" % user_id
    result = schema.execute(query)
    return result.data


# VULNERABLE: execute_query with string concatenation
def find_posts(author: str):
    query = "query { posts(author: \"" + author + "\") { id title } }"
    execute_query(query)
