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

jwt.sign({
  data: 'foobar'
}, 'secret', { expiresIn: 60 * 60 });

jwt.sign({
  data: 'foobar'
}, 'secret', { expiresIn: '1h' });

var decoded = jwt.verify(token, 'shhhh');
console.log(decoded.foo)
jwt.verify(token, 'shhhh', function(err, decoded){
  console.log(decoded.foo)
});
try {
  var decoded = jwt.verify(token, 'wrong-secret');
} catch(err){
  //err
}
var cert = fs.readFileSync('public.pem');
jwt.verify(token, cert, function(err, decoded){
  console.log(decoded.foo)
});
var cert = fs.readFileSync('public.pem');
jwt.verify(token, cert, { audience: 'urn:foo' }, function(err, decoded){
});
var cert = fs.readFileSync('public.pem');
jwt.verify(token, cert, { audience: 'urn:foo', issuer: 'urn:issuer' }, function(err, decoded){
});
var cert = fs.readFileSync('public.pem');
jwt.verify(token, cert, {}, function(){});











```

```
```

