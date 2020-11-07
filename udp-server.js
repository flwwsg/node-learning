const dgram = require('dgram');
const server = dgram.createSocket('udp4');

server.on('message', function (msg, rinfo) {
    console.log(`server got: ${msg} from ${rinfo.address} : ${rinfo.port}`);
    server.send('got it', 0, 6, rinfo.port, rinfo.address,function (error, bytes){
        if(error != null) {
            console.log(error);
        }
    });
});

server.on('listening', function () {
    const address = server.address();
    console.log(`server listening ${address.address} : ${address.port}`);
});

server.bind(8888);