'use strict';

const grpc = require('@grpc/grpc-js');
const loader = require('@grpc/proto-loader');
const path = require('path');
const commonDir = path.dirname(__dirname) + '/common';
const pkgDef = loader.loadSync(commonDir + '/grpc-recipe.proto');
const recipe = grpc.loadPackageDefinition(pkgDef).recipe;
const HOST = process.env.HOST || 'localhost';
const PORT = process.env.PORT || 4000;
const server = new grpc.Server();
server.addService(recipe.RecipeService.service, {
    getMetaData: (_call, cb) => {
        cb(null, {
            pid: process.pid,
        });
    },
    getRecipe: (call, cb) => {
        if (call.request.id !== 42) {
            return cb(new Error(`unknown recipe ${call.request.id}`));
        }
        cb(null, {
            id: 42,
            name: 'demo',
            steps: '1',
            ingredients: [
                {
                    id: 1,
                    name: 'test1',
                    quantity: '1',
                },
            ]
        });
    },
});
server.bindAsync(`${HOST}:${PORT}`,
    grpc.ServerCredentials.createInsecure(),
    (error, port) => {
        if (error) {
            throw error;
        }
        server.start();
        console.log(`producer running at http://${HOST}:${port}`);
    })
