
const fs = require('fs');
const url = require('url');
const querystring = require('querystring');
const xml2js = require('xml2js');
const formidable = require('formidable');

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

const handle404 = function (req, res) {
    res.writeHead(404);
    res.end('can not find it');
}

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


// 数据上传

// node 的 http 模块只对 http 报文的头部进行了解析，然后触发 request 事件。如果请求中还带有内容部分(如 POST 请求，它具有报头和内容)，内容部分需要用户自行接收和解析。
// 通过报头的 Transfer-Encoding或者 Content-Length 即可判断请求中是否带有内容

const hasBody = function (req) {
    return 'transfer-encoding' in req.headers || 'content-length' in req.headers;
}

// 报头结束后，报文内容会通过 data 事件触发
app = function (req, res) {
    if (hasBody(req)) {
        const buffers = [];
        req.on('data', function (chunk) {
            buffers.push(chunk);
        });
        req.on('end', function () {
            // 挂载在 req.rawBody 处
            req.rawBody = Buffer.concat(buffers).toString();
            handle(req, res);
        });
    } else {
        handle(req, res);
    }
}

// 表单数据, 请求头的 content-type 为 application/x-www-form-urlencoded
handle = function (req, res) {
    if (req.headers['content-type'] === 'application/x-www-form-urlencoded') {
        // 后续业务中直接访问 req.body 即可得到表单提交的数据
        req.body = querystring.parse(req.rawBody);
    }
    // TODO something (req, res);
}

// 其他格式, json, xml

let mime = function (req) {
    const str = req.headers['content-type'] || '';
    return str.split(';')[0];
};

// json
handle = function (req, res) {
    if (mime(req) === 'application/json') {
        try {
            req.body = JSON.parse(req.rawBody);
        } catch (e) {
            res.writeHead(400);
            res.end('invalid JSON');
            return;
        }
    }
    // TODO something(req, res);
}

// xml
handle = function (req, res) {
    if(mime(req) === 'application/xml') {
        xml2js.parseString(req.rawBody, function (err, xml) {
            if(err) {
                res.writeHead(400);
                res.end('invalid xml');
                return;
            }
            req.body = xml;
            // TODO something(req, res);
        })
    }
};


// 附件上传, 特殊表单与普通表单的差异在于该表单中可以含有 file 类型的控件，以及需要指定表单属性 enctype 为 multipart/form-data。
// 浏览器在遇到 multipart/form-data 表单提交时，构造的请求报文与普通表单完全不同。最为特殊的如下所示
//
// Content-Type: multipart/form-data; boundary=AaB03x
// Content-Length: 18231
//
// 表示本次提交的内容是由多部分构成的，其中 boundary=AaB03x 指定的是每部分内容的分界符，AaB03x是随机生成的一段字符串，报文体的内容将通过在它前面添加
// "--" (不包括引号) 进行分割，报文结束时在它前后都加上 "--" 表示结束。另外，Content-Length 的值必须确保是报文体的长度。

// 接收大小未知的数据量时，需要十分谨慎
app = function (req, res) {
    if(hasBody(req)) {
        const done = function () {
            handle(req, res);
        };

        if(mime(req) === 'application/json') {
            parseJSON(req, done);
        } else if (mime(req) === 'application/xml') {
            parseXML(req, done);
        } else if (mime(req) === 'multipart/form-data'){
            parseMultipart(req, done);
        }
    } else {
        handle(req, res);
    }
}

// formidable 基于流式处理解析报文，将接收到的文件写入系统临时文件夹中
app = function (req, res) {
    if(hasBody(req)) {
        if(mime(req) === 'multipart/form-data') {
            const form = new formidable.IncomingForm();
            form.parse(req, function (err, fields, files) {
                req.body = fields;
                req.files = files;
                handle(req, res);
            })
        } else {
            handle(req, res);
        }
    }
}


// 附件内存限制

let bytes = 1024;
app = function (req, res) {
    let received = 0;
    let len = req.headers['content-length'] ? parseInt(req.header['content-length'], 10) : null;
    if(len && len > bytes) {
        // 内容超过长度
        res.writeHead(413);
        res.end();
        return ;
    }
    req.on('data', function (chunk) {
        received += chunk.length;
        if(received > bytes) {
            req.destroy();
        }
    })

    handle(req, res);
}


// ## 路由解析
// MVC
// 如何根据 URL 做路由映射，有两个分支实现。一种是通过手工关联映射，另一种是自然关联映射。
// 前者会有一个对应的路由文件来将 URL 映射到对应的控制器，后者没有这样的文件。

// 1、手工映射
let  routes = [];
let use = function (path, action) {
    routes.push([path, action]);
}

use('/user/setting', exports.settings);
use('/setting/user', exports.settings);

// 在入口程序判断 URL，然后执行对应的逻辑，这样就完成了基本的路由映射过程
app = function (req, res) {
    const pathname = url.parse(req.url).pathname;
    for(let i = 0; i < routes.length; i++) {
        const route = routes[i];
        if (pathname === route[0]) {
            const action = route[1];
            action(req, res);
            return ;
        }
    }
    handle404(req, res);
}

// 使用正则匹配
let pathRegexp = function (path) {
    // 有点复杂的正则
    path = path
        .concat(strict ? '' : '/?')
        .replace(/\/\(/g, '(?:/')
        .replace(/(\/)?(\.)?:(\w+)(?:(\(.*?\)))?(\?)?(\*)?/g,
            function (_, slash, format, key, capture, optional, star) {
            slash = slash || '';
            return ''
                + (optional ? '' : slash)
                + '(?:'
                + (optional ? slash : '')
                + (format || '') + (capture || (format && '([^/.]+?)' || '([^/]+?)')) + ')'
                + (optional || '')
                + (star ? '(/*)?' : '');
        })
        .replace(/([\/.])/g, '\\$1')
        .replace(/\*/g, '(.*)');
    return new RegExp('^' + path + '$');
}

// 改进注册部分
use = function (path, action) {
    routes.push([pathRegexp(path), action]);
};

// 匹配部分
app = function (req, res) {
    const pathname = url.parse(req.url).pathname;
    for (let i = 0; i < routes.length; i++) {
        const route = routes[i];
        // 正则匹配
        if(route[0].exec(pathname)) {
            const action = route[1];
            action(req, res);
            return;
        }
    }
    handle404(req, res);
}

 // 参数解析
// 我仌希望在业务中能如下这样调用
use('/profile/:username', function (req, res) {
    const username = req.params.username;
    // TODO others
});

// 取出键值
pathRegexp = function (path) {
    const keys = [];
    // 有点复杂的正则
    path = path
        .concat(strict ? '' : '/?')
        .replace(/\/\(/g, '(?:/')
        .replace(/(\/)?(\.)?:(\w+)(?:(\(.*?\)))?(\?)?(\*)?/g,
            function (_, slash, format, key, capture, optional, star) {
                keys.push(key);
                slash = slash || '';
                return ''
                    + (optional ? '' : slash)
                    + '(?:'
                    + (optional ? slash : '')
                    + (format || '') + (capture || (format && '([^/.]+?)' || '([^/]+?)')) + ')'
                    + (optional || '')
                    + (star ? '(/*)?' : '');
            })
        .replace(/([\/.])/g, '\\$1')
        .replace(/\*/g, '(.*)');
    return {
        keys,
        regexp:  new RegExp('^' + path + '$')
    };
}

// 根据抽取的键值和实际的 URL 得到键值匹配到的实际值，设置到 req.params
app = function (req, res) {
    const pathname = url.parse(req.url).pathname;
    for(let i = 0; i < routes.length; i++) {
        const route = routes[i];
        const reg = route[0].regexp;
        const keys = route[0].keys;
        const matched = reg.exec(pathname);
        if(matched) {
            const params = {};
            for (let i = 0, l = keys.length; i < l; i++) {
                const value = matched[i+1];
                if(value) {
                    params[keys[i]] = value;
                }
            }
            req.params = params;
            const action = route[1];
            action(req, res);
            return;
        }
    }
    handle404(req, res);
}

// 2、自然映射。尽是路由不如无路由。实际上并非没有路由，而是路由按一种约定的方式自然而然的地实现了路由，无须维护


// ## restful
// 它将 DELETE 、PUT 请求方法引入设计中，参与资源的操作和更改资源的状态。
// 在 restful 设计中，资源的具体格式由请求报头中的 Accept 字段和服务器端的支持情况来决定。如
// Accept: application/json, application.xml
// rest 设计就是，通过 URL 设计资源、请求方法定义资源的操作，通过 Accept 决定资源的表现形式

// 示例
routes = {'all': []};
app = {};
app.use = function (path, action) {
    routes.all.push([pathRegexp(path), action]);
};

// 添加 get、put、delete、post 方法在 app 函数上
// 使用方式 app.get('路由', 业务函数) , app.put('路由', 业务函数);
['get', 'put', 'delete', 'post'].forEach(function (method) {
    routes[method] = [];
    app[method] = function (path, action) {
        routes[method].push([pathRegexp(path), action]);
    }
})

// 匹配函数
let match = function (req, res, pathname, routes) {
    for (let i = 0; i < routes.length; i++) {
        const route = routes[i];
        // 正则匹配
        const reg = route[0].regexp;
        const keys = routes[0].keys;
        const matched = reg.exec(pathname);
        if(matched) {
            // 抽取具体值
            const params = {};
            for (let i = 0, l = keys.length; i < l; i++) {
                const value = matched[i+1];
                if(value) {
                    params[keys[i]] = value;
                }
            }
            req.params = params;
            const action = route[1];
            action(req, res);
            return true;
        }
    }
    return false;
}

// 分发部分
app = function (req, res) {
    const pathname = url.parse(req.url).pathname;
    // 请求方法变为小写
    const method = req.method.toLowerCase();
    if(routes.hasOwnProperty(method)) {
        // 根据请求方法分发
        if(match(req, res, pathname, routes[method])) {
        } else {
            // 没有方法匹配，尝试用 all 来处理
            if(match(req, res, pathname, routes.all)) {
            }
        }
    } else {
        // 直接用 all 来处理
        if(match(pathname, routes.all)) {
            return ;
        }
        handle404(req, res);
    }
}

// ## middleware 中间件
// 最早的中间件定义是一种在操作系统上为应用软件提供服务的计算机软件。既不是操作系统的一部分，也不是应用软件的一部分，处于操作系统与应用软件之间，
// 让应用软件更好、更方便的使用底层服务。如今中间件的含义借指了这种封装底层细节，让上层提供更方便服务的意义，并非限定在操作系统层面。
// 这里主要指我们封装上文提及的所有 HTTP 请求细节处理的中间件，开发者可以脱离这部分细节，专注在业务上。

//
// // 示例
// app.use('路由', querystring, cookie, session, function (req, res) {
//     // TODO something
// })

app.use = function (path) {
    const handle = {
        // 路径
        path: pathRegexp(path),
        // 其它处理单元
        stack: Array.prototype.slice.call(arguments, 1),
    };
    routes.all.push(handle);
}

match = function (req, res, pathname, routes) {
    for (let i = 0; i < routes.length; i++) {
        const route = routes[i];
        const reg = route.path.regexp;
        const matched = reg.exec(pathname);
        if(matched) {
            // 将中间件数组交给 handle 方法处理
            handle(req, res, route.stack);
            return true;
        }
    }
    return false;
}

handle = function (req, res, stack) {
    const next = function () {
        const middleware = stack.shift();
        if(middleware) {
            // 传入 next 函数自身，使中间件能够执行结束后递归
            middleware(req, res, next);
        }
    };
    // start middleware
    next();
}

// 改进新的设计
// 示例
// app.use(querystring);
// app.use(cookie);
// app.use(session);
// app.get('路由', 业务处理);

app.use = function (path) {
    let handle;
    if(typeof path === 'string') {
        handle = {
            path: pathRegexp(path),
            stack: Array.prototype.slice.call(arguments, 1),
        };
    } else {
        handle = {
            path: pathRegexp('/'),
            stack: Array.prototype.slice.call(arguments, 0),
        }
    }
    routes.all.push(handle);
}

// 新的匹配过程
match = function (req, res, pathname, routes) {
    let stacks = [];
    for (let i = 0; i < routes.length; i++) {
        const route = routes[i];
        const reg = route.path.regexp;
        const matched = reg.exec(pathname);
        if(matched) {
            stacks = stacks.concat(route.stack);
        }
    }
    return stacks;
}

// 新的分发过程
app = function (req, res) {
    const pathname = url.parse(req.url).pathname;
    const method = req.method.toLowerCase();
    let stacks = match(pathname, routes.all);
    if(routes.hasOwnProperty(method)) {
        stacks.concat(match(pathname, routes[method]));
    }
    if(stacks.length) {
        handle(req, res, stacks);
    } else {
        handle404(req, res);
    }
}

// 异常处理

handle = function (req, res, stack) {
    const next = function (err) {
        if(err) {
            return handle500(err, req, res, stack);
        }
        const middleware = stack.shift();
        if(middleware) {
            try {
                middleware(req, res, next);
            } catch (ex) {
                next(err);
            }
        }
    }

    next();
}

// 中间件异步产生的异常需要自己传递出来
let session = function (req, res, next) {
    const id = req.cookies.sessionid;
    store.get(id, function (err, session) {
        if(err) {
            return next(err);
        }
        req.session = session;
        next();
    })
}

// 区分普通中间件和异常处理中间件， handle500 将对中间件按参数进行选择，然后递归执行
handle500 = function (err, req, res, stack) {
    stack = stack.filter(function (middleware) {
        return middleware.length === 4;
    })
    const next = function () {
        const middleware = stack.shift();
        if(middleware) {
            middleware(err, req, res, next);
        }
    };
    next();
}

// ## 中间件与性能
// 1、编写高效的中间件
// a、使用高效的方法
// b、缓存需要重复计算的结果
// c、避免不必要的计算

// 2、合理使用路由