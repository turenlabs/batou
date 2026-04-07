import { graphql, buildSchema } from 'graphql';
import { ApolloServer, gql } from 'apollo-server';
import { Request, Response } from 'express';

// VULNERABLE: GraphQL query built with string concatenation
export async function searchUser(req: Request, res: Response): Promise<void> {
  const username = req.query.username as string;
  const query = "query { user(name: \"" + username + "\") { id email role } }";
  const result = await graphql({ schema, source: query });
  res.json(result);
}

// VULNERABLE: GraphQL mutation with template literal interpolation
export async function updateUser(req: Request, res: Response): Promise<void> {
  const { id, role } = req.body;
  const mutation = `mutation { updateUser(id: "${id}", role: "${role}") { id role } }`;
  const result = await graphql({ schema, source: mutation });
  res.json(result);
}

// VULNERABLE: GraphQL query with template literal interpolation
export async function getPost(req: Request, res: Response): Promise<void> {
  const postId = req.params.id;
  const result = await graphql({ schema, source: `query { post(id: "${postId}") { title body } }` });
  res.json(result);
}
