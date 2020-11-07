const websocket = require('ws');

const wss = new websocket.Server({
    port: 8888,
});

wss.on('connection', function connection(ws) {
    wss.on('message', function incoming(msg) {
        console.log('received: %s', msg);
    });
    ws.send('received');
});




