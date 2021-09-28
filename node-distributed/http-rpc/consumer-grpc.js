'use strict';
const util = require('util');
const grpc = require('@grpc/grpc-js');
const server = require('fastify')();
const loader = require('@grpc/proto-loader');
const path = require('path');
const commonDir = path.dirname(__dirname) + '/common';
const pkgDef = loader.loadSync(commonDir + '/grpc-recipe.proto');
const recipe = grpc.loadPackageDefinition(pkgDef).recipe;
const HOST = process.env.HOST || 'localhost';
const PORT = process.env.PORT || 3000;
const TARGET = process.env.TARGET || 'localhost:4000';

const client = new recipe.RecipeService(
    TARGET,
    grpc.credentials.createInsecure(),
);

const getMetaData = util.promisify(client.getMetaData.bind(client));
const getRecipe = util.promisify(client.getRecipe.bind(client));

server.get('/', async () => {
    const [ meta, recipe ] = await Promise.all([
        getMetaData({}),
        getRecipe({ id: 42 }),
    ]);
    return {
        consumerPid: process.pid,
        producerData: meta,
        recipe
    }
});

server.listen(PORT, HOST, () => {
    console.log(`consumer running at http://${HOST}:${PORT}/`);
})
