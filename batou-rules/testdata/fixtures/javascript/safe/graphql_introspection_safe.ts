import { ApolloServer } from '@apollo/server';
import { typeDefs, resolvers } from './schema';

// SAFE: introspection disabled in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false,
});

server.listen().then(({ url }) => {
  console.log(`Server ready at ${url}`);
});
