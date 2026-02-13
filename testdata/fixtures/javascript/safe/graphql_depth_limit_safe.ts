import { ApolloServer } from '@apollo/server';
import depthLimit from 'graphql-depth-limit';
import { typeDefs, resolvers } from './schema';

// SAFE: depth limiting configured
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false,
  validationRules: [depthLimit(10)],
});
