const dgram = require('dgram');

const msg = Buffer.from('welcome to nodejs');
const client = dgram.createSocket('udp4');
client.send(msg, 0, msg.length, 8888, '127.0.0.1', function (error, bytes) {
    if(error != null) {
        console.log(`error occur: ${error}`);
    }
});

client.on('message', (msg, rinfo) => {
   console.log(`from address: ${rinfo.address}, port: ${rinfo.port}, message: ${msg}`)
});