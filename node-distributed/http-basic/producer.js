'use strict';

const server = require('fastify')();
const HOST = process.env.HOST || 'localhost';
const PORT = process.env.PORT || 4000;

console.log(`worker pid = ${process.pid}`);
server.get('/recipes/:id', async (req, reply) => {
  console.log(`worker request pid = ${process.pid}`);
  const id = Number(req.params.id);
  if (id !== 42) {
    reply.statusCode = 404;
    return { error: 'not found' };
  }
  return {
    producerPid: process.pid,
    recipe: {
      id,
      name: 'test',
      steps: '1',
      ingredients: [
        {
          id: 1,
          name: 'test',
          quantity: '1',
        },
      ],
    }
  }
});
server.listen(PORT, HOST, () => {
  console.log(`producer running at http://${HOST}:${PORT}`);
})
