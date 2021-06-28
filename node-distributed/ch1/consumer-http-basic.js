'use strict';
const server = require('fastify')();
const fetch = require('node-fetch');
const HOST = process.env.HOST || 'localhost';
const PORT = process.env.PORT || 3000;
const TARGET = process.env.TARGET || 'localhost:4000';

server.get('/', async () => {
    const req = await fetch(`http://${TARGET}/recipes/42`);
    const producerData = await req.json();
    return {
        consumerPid: process.pid,
        producerData,
    }
});

server.listen(PORT, HOST, () => {
    console.log(`consumer running at http://${HOST}:${PORT}/`);
})
