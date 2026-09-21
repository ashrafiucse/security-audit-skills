// Fixture: intentionally vulnerable GraphQL server (Apollo Server 3). FAKE data only.
const { ApolloServer, gql } = require('apollo-server-express');
const express = require('express');

const typeDefs = gql`
  type User { id: ID! email: String! passwordHash: String! role: String! }
  type Query {
    user(id: ID!): User
    allUsers: [User!]!
    adminDashboard(nonce: String): String
  }
  type Mutation {
    login(email: String!, password: String!): String
    resetPassword(email: String!): Boolean
  }
`;

const resolvers = {
  Query: {
    // SEC-03: IDOR — fetches by id with no ownership/scope check
    user: (_, { id }) => db.users.findById(id),
    // SEC-04: unbounded pagination — dumps every user row incl. passwordHash
    allUsers: () => db.users.all(),
    // SEC-05: admin field with no role check; echoes input back
    adminDashboard: (_, { nonce }) => `dashboard:${nonce}`,
  },
  Mutation: {
    // SEC-06: no rate limiting on login/reset (bypasses REST limiters)
    login: async (_, { email, password }) => issueToken(email, password),
    resetPassword: async (_, { email }) => true,
  },
};

const server = new ApolloServer({
  typeDefs,
  resolvers,
  // SEC-01: introspection + playground forced on (even in production builds)
  introspection: true,
  playground: true,
  // SEC-02: leaks error internals and partial stacktraces to clients
  formatError: (err) => ({
    message: err.message,
    extensions: err.extensions,
    stack: typeof err.stack === 'string' ? err.stack.split('\n').slice(0, 4) : undefined,
  }),
  // SEC-07: no validationRules → no depth/complexity limit (nested-query DoS)
  // SEC-08: cookie-session auth below, csrfPrevention not configured
});

const app = express();
app.use(require('cookie-session')({ name: 'sess', keys: ['dev-secret'] }));
server.applyMiddleware({ app, path: '/graphql' });
app.listen(4000);
