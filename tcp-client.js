const net = require('net');
const client = net.connect({ port: 8888}, function () {
    console.log('client connected');
    client.write('world!\n');
});

client.on('data', function (data) {
    console.log('received:', data.toString());
    client.end();
});

client.on('end', function () {
    console.log('client disconnected');
});
