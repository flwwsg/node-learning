'use strict';
const server = require('fastify')();
const fetch = require('node-fetch');
const HOST = process.env.HOST || 'localhost';
const PORT = process.env.PORT || 3000;
const TARGET = process.env.TARGET || 'localhost:4000';
const complexQuery = `query demo ($id: ID) {
    recipe(id: $id) {
        id
        name
        ingredients {
            name
            quantity
        }
    }
    pid
}`

server.get('/', async () => {
  const req = await fetch(`http://${TARGET}/graphql`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      query: complexQuery,
      variables: {
        id: 42
      },
    }),
  });
  const producerData = await req.json();
  return {
    consumerPid: process.pid,
    producerData,
  }
});

server.listen(PORT, HOST, () => {
  console.log(`consumer running at http://${HOST}:${PORT}/`);
})
