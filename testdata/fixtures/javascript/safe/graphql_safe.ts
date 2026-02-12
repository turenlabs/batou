import { graphql, buildSchema } from 'graphql';
import { Request, Response } from 'express';

// SAFE: GraphQL query using parameterized variables
export async function searchUser(req: Request, res: Response): Promise<void> {
  const username = req.query.username as string;
  const query = `query GetUser($name: String!) { user(name: $name) { id email role } }`;
  const result = await graphql({
    schema,
    source: query,
    variableValues: { name: username },
  });
  res.json(result);
}

// SAFE: GraphQL mutation using parameterized variables
export async function updateUser(req: Request, res: Response): Promise<void> {
  const { id, role } = req.body;
  const mutation = `mutation UpdateUser($id: ID!, $role: String!) { updateUser(id: $id, role: $role) { id role } }`;
  const result = await graphql({
    schema,
    source: mutation,
    variableValues: { id, role },
  });
  res.json(result);
}

// SAFE: Static query string with no user input
export async function listUsers(req: Request, res: Response): Promise<void> {
  const query = `query { users { id email } }`;
  const result = await graphql({ schema, source: query });
  res.json(result);
}
