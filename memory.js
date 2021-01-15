// test memory limit,  64 位的机器大约 1.4GB，32 位机器大约为 0.7GB
'use strict';
const hd = require('heapdump');
const path = require('path');

function writeSnapshot() {
    hd.writeSnapshot(path.join(path.join(__dirname, 'tmp'), Date.now().toString()+'.heapsnapshot'));
}

const format = (bytes) => {
    return (bytes / 1024 / 1024).toFixed(2) + "MB";
}

const showMem = function () {
    const mem = process.memoryUsage();
    console.log(`heapTotal: ${format(mem.heapTotal)}, heapUsed: ${format(mem.heapUsed)}, rss: ${format(mem.rss)}`);
}

// limit use
const useMem = function () {
    const size = 30*1024*1024;
    const arr = new Array(size);
    for (let i = 0; i < size; i++) {
        arr[i] = 0;
    }
    return arr;
}

// unlimited buffer

const unLimitedUseMem = function () {
    const size = 50*1024*1024;
    // buffer.alloc quicker than , buffer.from array
    const arr = Buffer.alloc(size);
    for (let i = 0; i < size; i++) {
        arr[i] = 0;
    }
    return arr;
}

const total = [];
for(let i = 0; i < 100; i++) {
    showMem();
    total.push(unLimitedUseMem());
}
// setTimeout(writeSnapshot, 1000);
// setTimeout(writeSnapshot, 200);
showMem();
setInterval(() => console.log(1), 10000);
// reference https://www.npmjs.com/package/heapdump