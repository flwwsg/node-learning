const net = require('net');

const server = net.createServer(function (socket) {
    socket.on("data", function (data) {
        socket.write('hello '+data );
    });

    socket.on('end', function () {
        console.log('exit');
    });

    socket.write('welcome to nodejs\n');
});

server.listen(8888, function () {
    console.log('server started');
})