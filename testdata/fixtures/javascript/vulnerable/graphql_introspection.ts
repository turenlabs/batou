import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from './schema';

// VULNERABLE: introspection enabled in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,
});

server.listen().then(({ url }) => {
  console.log(`Server ready at ${url}`);
});
