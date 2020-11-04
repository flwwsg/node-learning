// test memory limit,  64 位的机器大约 1.4GB，32 位机器大约为 0.7GB

const format = (bytes) => {
    return (bytes / 1024 / 1024).toFixed(2) + "MB";
}

const showMem = function () {
    const mem = process.memoryUsage();
    console.log(`heapTotal: ${format(mem.heapTotal)}, heapUsed: ${format(mem.heapUsed)}, rss: ${mem.rss}`);
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
    const size = 30*1024*1024;
    // buffer.alloc quicker than , buffer.from array
    const arr = Buffer.alloc(size);
    for (let i = 0; i < size; i++) {
        arr[i] = 0;
    }
    return arr;
}

const total = [];
for(let i = 0; i < 50; i++) {
    showMem();
    total.push(unLimitedUseMem());
}
showMem();