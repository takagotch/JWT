### JSONWebToken
---

https://github.com/auth0/node-jsonwebtoken


```
npm install jsonwebtoken

```

```js
var jwt = require('jsonwebtoken');
var token = jwt.sign({ foo: 'bar' }, 'shhhhh');

var cert = fs.readFileSync('private.key');
var token = jwt.sign({ foo: 'bar' }, cert, { algorithm: 'RS256'});

jwt.sign({ foo: 'bar' }, cert, { algorithm: 'RS256' }, function(err, token){
  console.log(token);
});

var older_token = jwt.sign({ foo: 'bar', iat: Math.floor(Date.now() / 1000) - 30 }, 'shhhh');

jwt.sing({
  exp: Math.floor(Date.now() / 1000) + (60 * 60),
  data: 'foobar'
}, 'secret');




```

```
```

