'use strict';

const server = require('fastify')();
const graphql = require('fastify-gql');
const fs = require('fs');
const path = require('path');
const HOST = process.env.HOST || 'localhost';
const PORT = process.env.PORT || 4000;
const schema = fs.readFileSync(path.dirname(__dirname) + '/common/graphql-schema.gql').toString();

const resolvers = {
    Query: {
        pid: () => process.pid,
        recipe: async (_obj, { id }) => {
            if (id !== '42') throw new Error(`recipe ${id} not found`);
            return {
                id,
                name: 'demo',
                steps: '1',
            }
        },
    },
    Recipe: {
        ingredients: async obj => {
            return (obj.id !== '42') ? [] : [
                {
                    id: 1,
                    name: 'test1',
                    quantity: '1',
                },
                {
                    id: 2,
                    name: 'test2',
                },
            ]
        }
    }
}
server
    .register(graphql, { schema, resolvers, graphiql: true })
    .listen(PORT, HOST, () => {
        console.log(`producer running at http://${HOST}:${PORT}/graphql`);
    });
