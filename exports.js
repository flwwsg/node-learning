// test exports
const change = function (a) {
    a = 100;
    console.log(a);
}

const a = 200;
change(a);
console.log(a);