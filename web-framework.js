
const fs = require('fs');
const url = require('url');

// 简单 http 框架
const http = require('http');
http.createServer(function (req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end('hello world\n');
}).listen(1337, '127.0.0.1');

console.log('server running at http://127.0.0.1:1337')

// 应用可能无限地复杂，但只要最终结果返回一个上面的函数作为参数，传递给 createServer() 方法作为 request 事件的侦听器就可以了。

// 通过请求方法决定响应行为

let app = function (req, res) {
    switch (req.method) {
        case 'POST':
            update(req, res);
            break;
        case 'DELETE':
            remove(req, res);
        case 'PUT':
            create(req, res);
        case 'GET':
        default:
            get(req, res);
    }
}

// 路径解析
// 1. 静态文件服务器，根据路径去查找磁盘中的文件，然后将其响应给客户端

app = function (req, res) {
    const pathname = url.parse(req.url).pathname;
    fs.readFile(path.join(ROOT, pathname), function (err, file) {
        if(err) {
            res.writeHead(404);
            res.send('找不到文件');
            return ;
        }
        res.writeHead(200);
        res.send(file);
    });
}

// 2. 根据路径来选择控制器，它预设路径为控制器和行为的组合，无须额外配置路由信息。
// 如 /controller/action/a/b/c
app = function (req, res) {
    const pathname = url.parse(req.url).pathname;
    const paths = pathname.split('/');
    const controller = paths[1] || 'index';
    const action = paths[2] || 'index';
    const args = paths.slice(3);
    if (handles[controller] && handles[controller][action]) {
        handles[controller][action].apply(null, [req, res].concat(args));
    } else {
        res.writeHead(500);
        res.send('找不到控制器');
    }
}

// 这样业务只关心具体业务实现, eg
handles.index = {};
handles.index.index = function (req, res, foo, bar) {
    res.writeHead(200);
    res.send(foo);
}

// 查询字符串
// node 提供了 querystring 模块用于处理这部分数据
// const query = url.parse(req.url, true).query;
app = function (req, res) {
    req.query = url.parse(req.url, true).query;
    handle(req, res);
}

// cookie
// cookie 的处理分为
// 1、服务器向客户端发送 cookie
// 2、浏览器将 cookie 保存
// 3、之后每次浏览器都会将 cookie 发向服务器端

// 序列化 cookie
const serialize = function (name, val, opt) {
    const pairs = [name + '=' + encode(val)];
    opt = opt || {};
    if(opt.maxAge) {
        pairs.push('Max-Age=' + opt.maxAge);
    }
    if(opt.domain) {
        pairs.push('Domain=' + opt.domain);
    }
    if(opt.path) {
        // 表示这个 cookie 影响到的路径，当前访问路径不满足该匹配时，浏览器不发送当前 cookie
        pairs.push('Path=' + opt.path);
    }
    if(opt.expires) {
        pairs.push('Expires=' + opt.expires.toUTCString());
    }
    if(opt.httpOnly) {
        // 告知浏览器不允许通过脚本 document.cookie 去更改这个 cookie 值，事实上，设置 HttpOnly 后，这个值在 document.cookie中不可见，
        // 但在 HTTP 请求过程中，仍然会发送这个 cookie 到服务器端
        pairs.push('HttpOnly');
    }
    if(opt.secure) {
        // 为 True时，表示在 HTTP 中是无效的，HTTPS 中才有效
        pairs.push('Secure');
    }
    return pairs.join('; ');
}

// cookie 解析
const parseCookie = function (cookie) {
    let cookies = {};
    if (!cookie){
        return cookies;
    }
    const list = cookie.split(';');
    for (let i = 0; i < list.length; i++) {
        const pair = list[i].split('=');
        cookies[pair[0].trim()] = pair[1];
    }
    return cookies;
}

// 在业务逻辑代码执行前，将其挂载在 req 对象上，让业务代码可以直接访问。
app = function (req, res) {
    req.cookies = parseCookie(req.headers.cookie);
    handle(req, res);
}

// 业务处理如下
let handle = function (req, res) {
    res.writeHead(200);
    if(!req.cookies.isVisit) {
        res.send('welcome to zoo');
    } else {
        // TODO
    }
};

// 由于 cookie 的实现机制，一旦服务器商向客户端发送了设置 cookie 的意图，除非 cookie 过期，否则客户端每次请求都会发送这些 cookie 到服务器端，
// 因此如果设置cookie 过多，将会导致报头较大。大多数 cookie 并不需要每次都用上，因为这会造成带宽的部分浪费。以静态文件最为典型，
// 静态文件的业务定位几乎不关心状态， cookie 对它而言几乎是无用的，但是一旦有cookie 设置到相同域下，它的请求中就会带上 cookie。
// 好在 cookie 在设计时限定了它的域，只有域名相同时才会发送。
// 为避免 cookie 带来的性能影响，为不需要 cookie 的组件换个域名可以实现减少无效 cookie 的传输。所以很多网站的静态文件会有特别的域名，使得业务相关的 cookie 不再影响 静态资源。
// 当然换用额外的域名带来的好处不只这点，还可以突破浏览器下载线程数量的限制，因为域名不同，可以将下载线程数翻倍。不过，换用额外域名会多一次 DNS 查询。


// session
// 为了解决cookie敏感数据的问题， session 应运而生。 session 的数据只保留在服务器端，客户端无法修改，这样数据的安全性得到一定保障，数据也无须在协议中每次传递。
// 如何将每个客户和服务器中的数据一一对应起来，有常见的2种实现方式

// 1. 基于 cookie 实现用户和数据的映射
let sessions = {};
let key = 'session_id';
const EXPIRES = 20 * 60 * 1000; // 2 hours
const generate = function () {
    let session = {};
    session.id = (new Date()).getTime() + Math.random();
    session.cookie = {
        expire: (new Date()).getTime() + EXPIRES
    };
    sessions[session.id] = session;
    return session;
};

// 每个请求到来时，检查 cookie 中的口令与服务端的数据，如果过期，就重新生成
app = function (req, res) {
    const id = req.cookies[key];
    if(!id) {
        req.session = generate();
    } else {
        let session = sessions[id];
        if (session) {
            if(session.cookie.expire > (new Date()).getTime()) {
                // 更新超时时间
                session.cookie.expire = (new Date()).getTime() + EXPIRES;
                req.session = session;
            } else {
                // 超时了
                delete sessions[id];
                req.session = generate();
            }
        } else {
            // session 过期或者口令不对，重新生成
            req.session = generate();
        }
    }
}

// 响应客户端时设置新的值,以便下次请求时能够对应服务器端的数据.
let writeHead = res.writeHead;
res.writeHead = function () {
    let cookies = res.getHeader('Set-Cookie');
    const session =serialize('Set-Cookie', req.session.id);
    cookies = Array.isArray(cookies) ? cookies.concat(session) : [cookies, session];
    res.setHeader('Set-Cookie', cookies);
    return writeHead.apply(this, arguments);
};

handle = function (req, res) {
    if(!req.session.isVisit) {
        res.session.isVisit = true;
        res.writeHead(200);
        res.send('welcome to zoo');
    } else {
        res.writeHead(200);
        res.end('welcome to zoo again');
    }
};

// 这样在 session 中保存的数据比直接在 cookie 中保存数据要安全得多。这种实现方案依赖 cookie 实现，而且也是目前大多数 web 应用的方案。


// 2.通过查询字符串实现浏览器端和服务端数据的对应。

// 它的原理是检查请求的查询字符串，如果没有值，会先生成新的带值的 URL，如下

const getURL = function (_url, key, value) {
    const obj = url.parse(_url, true);
    obj.query[key] = value;
    return url.format(obj);
}

// 然后形成跳转，让客户端重新发起请求

app = function (req, res) {
    const redirect = function (url) {
        res.setHeader('Location', url);
        res.writeHead(302);
        res.end();
    };

    const id = req.query[key];
    if(!id) {
        const session = generate();
        redirect(getURL(req.url, key, session.id));
    } else {
        const session = sessions[id];
        if(session) {
            if(session.cookie.expire > (new Date()).getTime()) {
                // 更新过期时间
                session.cookie.expire = (new Date()).getTime() + EXPIRES;
                req.session = session;
                handle(req, res);
            } else {
                // 超时
                delete sessions[id];
                const session = generate();
                redirect(getURL(req.url, key, session.id));
            }
        } else {
            // session过期或者口令不对
            const session = generate();
            redirect(getURL(req.url, key, session.id));
        }

    }
}
// 这种方案带来的风险远大于基于 cookie 实现的风险，因为只要将地址栏中的地址发给另外一个人，那么他就拥有跟你相同的身份。 cookie 的方案在换了浏览器或者换了电脑之后无法生效，相对较为安全

// session 与内存。为了解决性能问题和 session 数据无法跨进程共享的问题，常用方案是将 session 集中化，将原本可能分散在多个进程里的数据，统一移到集中的数据存储中。常用 redis memcached。
// 采用缓存方案的 session

app = function (req, res) {
    const id = req.cookies[key];
    if(!id) {
        req.session = generate();
        handle(req, res);
    } else {
        // 异步存取 session
        store.get(id, function (err, session) {
            if(session) {
                if(session.cookie.expire > (new Date()).getTime()) {
                    // 更新超时时间
                    session.cookie.expire = (new Date()).getTime() + EXPIRES;
                    req.session = session;
                } else {
                    delete sessions[id];
                    req.session = generate();
                }
            } else {
                req.session = generate();
            }
            handle(req, res);
        })
    }
}

// 响应时，将新 session 保存回缓存中

writeHead = res.writeHead;
res.writeHead = function () {
    let cookies = res.getHeader('Set-Cookie');
    const session = serialize('Set-Cookie', req.session.id);
    cookies = Array.isArray(cookies) ? cookies.concat(session) : [cookies, session];
    res.setHeader('Set-Cookie', cookies);
    store.save(req.session);
    return writeHead.apply(this, arguments);
}

// session 与 安全。如果 web 应用的用户十分多，自行设计的随机算法的一些口令值就有理论机会命中有效的口令值。一旦口令被伪造，服务端的数据也可能间接被利用。
// 如何让这个口令更加安全，一种做法是将这个口令通过私钥加密进行签名，使得伪造成本较高。

// 通过私钥签名，由 . 分割原值和签名
let sign = function (val, secret) {
    return val + '.' + crypto
        .createHmac('sha256', secret)
        .update(val)
        .digest('base64')
        .replace(/\=+$/, '');
};

// 响应时，设置 session 到 cookie 中
let val = sign(req.sessionID, secret);
res.setHeader('Set-Cookie', cookie.serialize(key, val));

// 接收请求时， 检查签名，对比用户提交的值
let unsign = function (val, secret) {
    const str = val.slice(0, val.lastIndexOf('.'));
    return sign(str, secret) === val ? str : false;
}

// 缓存
// 通过设置 expires、cache-control 控制缓存
handle = function (req, res) {
    fs.readFile(filename, function (err, file) {
        const expires = new Date();
        // 10年
        expires.setTime(expires.getTime() + 10 * 365 * 24 * 60 * 60 * 1000);
        res.setHeader('Expires', expires.toUTCString());
        res.writeHead(200, 'OK');
        res.end(file);
    });
}

// cache-control
handle = function (req, res) {
    fs.readFile(filename, function (err, file) {
        res.setHeader("Cache-Control", "max-age=" + 10 * 365 * 24 * 60 * 60 * 1000);
        res.writeHead(200, "OK");
        res.end(file);
    })
}

// 更新缓存
// 因为浏览器是根据  URL 进行缓存，一旦内容有所更新时，可以让浏览器发起新的 URL 请求，使得新内容能够被客户端更新，主要有
// 1. 每次发布，路径中跟随 web 应用的版本号： http://url.com/?v=20201111
// 2. 每次发布，路径中跟随该文件内容的 hash 值: http://url.com/?hash=xxxxxxx (推荐此方案)


// basic 认证
// 在 basic 认证中，它会将用户和密码部分组合：username + ":" + password。然后进行 Base64 编码
const encodeBasic = function (username, password) {
    return Buffer.from(username + ':' + password).toString('base64');
}

// 首次访问时
app = function (req, res) {
    const auth = req.headers['authorization'] || '';
    const parts = auth.split(' ');
    const method = parts[0] || ''; // basic
    const encoded = parts[1] || ''; // base64编码后的字符串
    const decoded = Buffer.from(encoded, 'base64').toString('utf-8').split(':');
    const user = decoded[0];
    const pass = decoded[1];
    if(!checkUser(user, pass)) {
        res.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
        res.end();
    } else {
        handle(req, res);
    }

}
