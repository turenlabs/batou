import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from './schema';

// VULNERABLE: no depth limiting or complexity analysis configured
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false,
});
