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
jwt.verify(token, 'wrong-secret', function(err, decoded){
  // err
});
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
jwt.verify(token, cert, { algotithms: ['RS256'] }, function(err, payload){
});
var jwksClient = require('jwks-rsa');
var clent = jwksClient({
  jwksUri: 'https://sandrino.auth0.com/.well-known/jwks.json'
});
functoin getKey(header, callback){
  client.getSigningKey(header.kid, function(err, key){
    var signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}
jwt.verify(token, getKey, options, function(err, decoded){
  console.log(decoded.foo)
});




var decoded = jwt.decode(token);
var decoded = jwt.decode(token, {complete: true});
console.log(decoded.header);
console.log(decoded.payload);

jwt.verify(token, 'shhhh', function(err, decoded){
  if(err){
    /*
      err = {
        name: 'TokenExpiredError',
        message: 'jwt expired',
        expiredAt: 1111111111
      }
    */
  }
});

jwt.verify(token, 'shhhhh', function(err, decoded){
  if(err){
    /*
      err = {
        name: 'JsonWebTokenError',
        message: 'jwt malformed'
      }
    */
  }
});

jwt.verify(token, 'shhhh', function(err, decoded){
  if(err){
    /*
      err = {
        name: 'NotBeforeError',
        message: 'jwt not active',
        date: 2018-10-04T16:10:44:000Z
      }
    */
  }
});

```

```
```

