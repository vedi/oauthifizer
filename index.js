var
  _ = require('lodash'),
  util = require('util'),
  Q = require('q'),
  oauth2orize = require('oauth2orize'),
  passport = require('passport'),
  LocalStrategy = require('passport-local').Strategy,
  BasicStrategy = require('passport-http').BasicStrategy,
  ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy,
  BearerStrategy = require('passport-http-bearer').Strategy;

function OAuth2(authDelegate) {
  this.passport = passport;
  this.authDelegate = authDelegate;

  /**
   * LocalStrategy
   *
   * This strategy is used to authenticate users based on a username and password.
   * Anytime a request is made to authorize an application, we must ensure that
   * a user is logged in before asking them to approve the request.
   */
  passport.use(new LocalStrategy(
    function(username, password, done) {
      Q.denodeify(authDelegate.findUser.bind(authDelegate))(({login: username, password: password}))
        .then(function(user) {
          return user ? user : false;
        })
        .nodeify(done)
      ;
    }
  ));

  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done) {
    Q.denodeify(authDelegate.findUser.bind(authDelegate))({
      id: id
    })
      .then(function (user) {
        return done(null, user);
      })
      .catch(function (err) {
        return done(err);
      })
    ;
  });

  /**
   * BasicStrategy & ClientPasswordStrategy
   *
   * These strategies are used to authenticate registered OAuth clients.  They are
   * employed to protect the `token` endpoint, which consumers use to obtain
   * access tokens.  The OAuth 2.0 specification suggests that clients use the
   * HTTP Basic scheme to authenticate.  Use of the client password strategy
   * allows clients to send the same credentials in the request body (as opposed
   * to the `Authorization` header).  While this approach is not recommended by
   * the specification, in practice it is quite common.
   */

  passport.use(new BasicStrategy(
    function (login, password, done) {
      Q.denodeify(authDelegate.findUser.bind(authDelegate))(({login: login, password: password}))
        .then(function(user) {
          return user ? user : false;
        })
        .nodeify(done)
      ;
    }
  ));

  passport.use(new ClientPasswordStrategy(
    function (clientId, clientSecret, done) {
      Q.denodeify(authDelegate.findClient.bind(authDelegate))({
        clientId: clientId,
        clientSecret: clientSecret
      })
        .nodeify(done)
      ;
    }
  ));

  /**
   * BearerStrategy
   *
   * This strategy is used to authenticate users based on an access token (aka a
   * bearer token).  The user must have previously authorized a client
   * application, which is issued an access token to make requests on behalf of
   * the authorizing user.
   */
  passport.use(new BearerStrategy(
    function (accessToken, done) {
      Q.denodeify(authDelegate.findUserByToken.bind(authDelegate))({accessToken:accessToken})
        .then(function (result) {
          return done(null, result.obj, result.info)
        })
        .catch(function (err) {
          return done(err);
        })
      ;
    }
  ));


// create OAuth 2.0 server
  this.server = oauth2orize.createServer();

  this.server.serializeClient(function(client, done) {
    return done(null, client.clientId);
  });

  this.server.deserializeClient(function(id, done) {
    Q.denodeify(authDelegate.findClient.bind(authDelegate))({
      clientId: id,
      clientSecret: false
    })
      .then(function (client) {
        return done(null, client);
      })
      .catch(function (err) {
        return done(err);
      })
    ;
  });

  this.server.grant(oauth2orize.grant.code(function(client, redirectUri, user, ares, done) {
    var codeValue = authDelegate.generateTokenValue();

    Q.denodeify(authDelegate.createAuthorizationCode.bind(authDelegate))({
        user: user,
        client: client,
        scope: ares.scope,
        redirectUri: redirectUri,
        codeValue: codeValue
      })
      .then(function () {
        return done(null, codeValue);
      })
      .catch(function (err) {
        return done(err);
      })
    ;
  }));

  this.server.exchange(oauth2orize.exchange.code(function(client, codeValue, redirectUri, done) {
    var context = {
      client: client,
      codeValue: codeValue,
      redirectUri: redirectUri,
      scope: undefined,
      tokenValue: undefined,
      refreshTokenValue: undefined,
      authorizationCode: undefined
    };
    Q.denodeify(authDelegate.findAuthorizationCode.bind(authDelegate))(context)
      .then(function (result) {
        if (!result) {
          throw false;
        }
        context.authorizationCode = result;
        context.scope = result.scope;
      })
      .then(function () {
        return Q.denodeify(authDelegate.cleanUpTokens.bind(authDelegate))(context);
        return done(null, codeValue);
      })
      .then(function () {
        context.tokenValue = authDelegate.generateTokenValue();
        context.refreshTokenValue = authDelegate.generateTokenValue();
        return Q.denodeify(authDelegate.createTokens.bind(authDelegate))(context)
      })
      .then(function () {
        return Q.denodeify(authDelegate.getTokenInfo.bind(authDelegate))(context)
      })
      .then(function (tokenInfo) {
        return done(null, context.tokenValue, context.refreshTokenValue, tokenInfo);
      })
      .catch(function (err) {
        if (err === false) {
          return done(null, false);
        } else {
          return done(err);
        }
      })
    ;
  }));

  // Exchange login & password for access token.

  this.server.exchange(oauth2orize.exchange.password(function (client, login, password, scope, done) {
    var context = {
      client: client,
      scope: scope,
      tokenValue: undefined,
      refreshTokenValue: undefined,
      user: undefined
    };

    Q.denodeify(authDelegate.findUser.bind(authDelegate))({login: login, password: password})
      .then(function (result) {
        if (!result) {
          throw false;
        }
        context.user = result;
        return Q.denodeify(authDelegate.cleanUpTokens.bind(authDelegate))(context);
      })
      .then(function () {
        context.tokenValue = authDelegate.generateTokenValue();
        context.refreshTokenValue = authDelegate.generateTokenValue();
        return Q.denodeify(authDelegate.createTokens.bind(authDelegate))(context)
      })
      .then(function () {
        return Q.denodeify(authDelegate.getTokenInfo.bind(authDelegate))(context)
      })
      .then(function (tokenInfo) {
        return done(null, context.tokenValue, context.refreshTokenValue, tokenInfo);
      })
      .catch(function (err) {
        if (err === false) {
          return done(null, false);
        } else {
          return done(err);
        }
      })
    ;
  }));

// Exchange refreshToken for access token.
  this.server.exchange(oauth2orize.exchange.refreshToken(function (client, refreshToken, scope, done) {
    var context = {
      client: client,
      scope: scope,
      tokenValue: undefined,
      refreshTokenValue: undefined,
      user: undefined
    };
    Q.denodeify(authDelegate.findUserByToken.bind(authDelegate))({refreshToken: refreshToken})
      .then(function (result) {
        if (result.obj === false) {
          throw false;
        }
        context.user = result.obj;
        return Q.denodeify(authDelegate.cleanUpTokens.bind(authDelegate))(context);
      })
      .then(function () {
        context.tokenValue = authDelegate.generateTokenValue();
        context.refreshTokenValue = authDelegate.generateTokenValue();
        return Q.denodeify(authDelegate.createTokens.bind(authDelegate))(context)
      })
      .then(function () {
        return Q.denodeify(authDelegate.getTokenInfo.bind(authDelegate))(context)
      })
      .then(function (tokenInfo) {
        return done(null, context.tokenValue, context.refreshTokenValue, tokenInfo);
      })
      .catch(function (err) {
        if (err === false) {
          return done(null, false);
        } else {
          return done(err);
        }
      })
    ;
  }));
}

util.inherits(OAuth2, Object);


OAuth2.prototype._bindAfterAuthorization = function(req, res, next) {
  if (this.authDelegate.afterAuthorization) {
    var _this = this;
    // proxy end()
    var end = res.end;
    res.end = function(chunk, encoding) {
      _this.authDelegate.afterAuthorization.call(_this.authDelegate, res);
      res.end = end;
      res.end(chunk, encoding);
    }
  }
  next();
};

OAuth2.prototype._bindAfterDecision = function(req, res, next) {
  if (this.authDelegate.afterDecision) {
    var _this = this;
    // proxy end()
    var end = res.end;
    res.end = function(chunk, encoding) {
      _this.authDelegate.afterDecision.call(_this.authDelegate, res);
      res.end = end;
      res.end(chunk, encoding);
    }
  }
  next();
};

OAuth2.prototype._bindAfterToken = function(req, res, next) {
  if (this.authDelegate.afterToken) {
    var _this = this;
    // proxy end()
    var end = res.end;
    res.end = function(chunk, encoding) {
      data = JSON.parse(chunk);
      _this.authDelegate.afterToken.call(_this.authDelegate, data, res);
      res.end = end;
      res.end(chunk, encoding);
    }
  }
  next();
};


// user authorization endpoint
//
// `authorization` middleware accepts a `validate` callback which is
// responsible for validating the client making the authorization request.  In
// doing so, is recommended that the `redirectURI` be checked against a
// registered value, although security requirements may vary accross
// implementations.  Once validated, the `done` callback must be invoked with
// a `client` instance, as well as the `redirectURI` to which the user will be
// redirected after an authorization decision is obtained.
//
// This middleware simply initializes a new authorization transaction.  It is
// the application's responsibility to authenticate the user and render a dialog
// to obtain their approval (displaying details about the client requesting
// authorization).  We accomplish that here by routing through `ensureLoggedIn()`
// first, and rendering the `dialog` view.
OAuth2.prototype.getAuthorization = function() {
  var _this = this;
  return [
    _.bind(_this.authDelegate.ensureLoggedIn, _this.authDelegate),
    _.bind(_this._bindAfterAuthorization, _this),
    this.server.authorization(function(clientId, redirectUri, done) {
      Q.denodeify(_this.authDelegate.findClient.bind(_this.authDelegate))({
        clientId: clientId,
        clientSecret: false
      })
        .then(function (client){
          if (client === false) {
            throw false;
          }
          done(null, client, redirectUri);
        })
        .catch(function (err) {
          if (err === false) {
            return done(null, false);
          } else {
            return done(err);
          }
        })
      ;
    }),
    _.bind(_this.authDelegate.approveClient, _this.authDelegate)()
  ];
};

// user decision endpoint
//
// `decision` middleware processes a user's decision to allow or deny access
// requested by a client application.  Based on the grant type requested by the
// client, the above grant middleware configured above will be invoked to send
// a response.

OAuth2.prototype.getDecision = function() {
  return [
    _.bind(this.authDelegate.ensureLoggedIn, this.authDelegate),
    _.bind(this._bindAfterDecision, this),
    this.server.decision()
  ];
};

// token endpoint
//
// `token` middleware handles client requests to exchange authorization grants
// for access tokens.  Based on the grant type being exchanged, the above
// exchange middleware will be invoked to handle the request.  Clients must
// authenticate when making requests to this endpoint.

OAuth2.prototype.getToken = function() {
  return [
    passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
    _.bind(this._bindAfterToken, this),
    this.server.token(),
    this.server.errorHandler()
  ];
};

OAuth2.passport = passport;

module.exports = OAuth2;

