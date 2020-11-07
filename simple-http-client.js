const http = require('http');

const options = {
    hostname: '127.0.0.1',
    port: 1337,
    path: '/',
    method: 'GET'
};

const req = http.request(options, function (res) {
    console.log(`status: ${res.statusCode}`);
    console.log(`headers: ${JSON.stringify(res.headers)}`);
    res.setEncoding('utf8');
    res.on('data', function (chunk) {
        console.log(chunk);
    })
})
req.end();