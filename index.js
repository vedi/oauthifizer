'use strict';

var _ = require('lodash');
var Bb = require('bluebird');
var oauth2orize = require('oauth2orize');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var BasicStrategy = require('passport-http').BasicStrategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var BearerStrategy = require('passport-http-bearer').Strategy;

class OAuth2 {

  constructor(authDelegate) {
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
      (username, password, done) => {
        authDelegate
          .findUser({login: username, password: password})
          .then((user) => {
            return user ? user : false;
          })
          .asCallback(done)
        ;
      }
    ));

    passport.serializeUser((user, done) => {
      done(null, user.id);
    });

    passport.deserializeUser((id, done) => {
      authDelegate
        .findUser({
          id: id
        })
        .then((user) => {
          return done(null, user);
        })
        .catch((err) => {
          err.status = err.status || 401;
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
      (login, password, done) => {
        authDelegate
          .findUser({login: login, password: password})
          .then((user) => {
            return user ? user : false;
          })
          .asCallback(done)
        ;
      }
    ));

    passport.use(new ClientPasswordStrategy(
      (clientId, clientSecret, done) => {
        authDelegate
          .findClient({
            clientId: clientId,
            clientSecret: clientSecret
          })
          .asCallback(done)
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
      (accessToken, done) => {
        return authDelegate
          .findUserByToken({accessToken: accessToken})
          .then((result) => {
            return done(null, result.obj, result.info)
          })
          .catch((err) => {
            err.status = err.status || 401;
            return done(err);
          })
          ;
      }
    ));


  // create OAuth 2.0 server
    this.server = oauth2orize.createServer();

    this.server.serializeClient((client, done) => {
      return done(null, client.clientId);
    });

    this.server.deserializeClient((id, done) => {
      authDelegate
        .findClient({
          clientId: id,
          clientSecret: false
        })
        .then((client) => {
          return done(null, client);
        })
        .catch((err) => {
          err.status = err.status || 401;
          return done(err);
        })
      ;
    });

    this.server.grant(oauth2orize.grant.code((client, redirectUri, user, ares, done) => {
      var codeValue = authDelegate.generateTokenValue();

      authDelegate
        .createAuthorizationCode({
          user: user,
          client: client,
          scope: ares.scope,
          redirectUri: redirectUri,
          codeValue: codeValue
        })
        .then(() => {
          return done(null, codeValue);
        })
        .catch((err) => {
          err.status = err.status || 401;
          return done(err);
        })
      ;
    }));

    this.server.exchange(oauth2orize.exchange.code((client, codeValue, redirectUri, done) => {
      var context = {
        client: client,
        codeValue: codeValue,
        redirectUri: redirectUri,
        scope: undefined,
        tokenValue: undefined,
        refreshTokenValue: undefined,
        authorizationCode: undefined
      };
      authDelegate
        .findAuthorizationCode(context)
        .then((result) => {
          if (!result) {
            return Bb.reject(false);
          }
          context.authorizationCode = result;
          context.scope = result.scope;
        })
        .then(() => {
          return authDelegate.cleanUpTokens(context);
        })
        .then(() => {
          context.tokenValue = authDelegate.generateTokenValue();
          context.refreshTokenValue = authDelegate.generateTokenValue();
          return authDelegate.createTokens(context);
        })
        .then(() => {
          return authDelegate.getTokenInfo(context);
        })
        .then((tokenInfo) => {
          return done(null, context.tokenValue, context.refreshTokenValue, tokenInfo);
        })
        .catch((err) => {
          if (err === false) {
            return done(null, false);
          } else {
            err.status = err.status || 401;
            return done(err);
          }
        })
      ;
    }));

    // Exchange login & password for access token.

    this.server.exchange(oauth2orize.exchange.password((client, login, password, scope, done) => {
      var context = {
        client: client,
        scope: scope,
        tokenValue: undefined,
        refreshTokenValue: undefined,
        user: undefined
      };

      authDelegate
        .findUser({login: login, password: password})
        .then((result) => {
          if (!result) {
            throw false;
          }
          context.user = result;
          return authDelegate.cleanUpTokens(context);
        })
        .then(() => {
          context.tokenValue = authDelegate.generateTokenValue();
          context.refreshTokenValue = authDelegate.generateTokenValue();
          return authDelegate.createTokens(context);
        })
        .then(() => {
          return authDelegate.getTokenInfo(context);
        })
        .then((tokenInfo) => {
          return done(null, context.tokenValue, context.refreshTokenValue, tokenInfo);
        })
        .catch((err) => {
          if (err === false) {
            return done(null, false);
          } else {
            err.status = err.status || 401;
            return done(err);
          }
        })
      ;
    }));

// Exchange refreshToken for access token.
    this.server.exchange(oauth2orize.exchange.refreshToken((client, refreshToken, scope, done) => {
      var context = {
        client: client,
        scope: scope,
        tokenValue: undefined,
        refreshTokenValue: undefined,
        user: undefined
      };

      return authDelegate
        .findUserByToken({refreshToken: refreshToken})
        .then((result) => {
          if (result.obj === false) {
            throw false;
          }
          context.user = result.obj;
          return authDelegate.cleanUpTokens(context);
        })
        .then(() => {
          context.tokenValue = authDelegate.generateTokenValue();
          context.refreshTokenValue = authDelegate.generateTokenValue();
          return authDelegate.createTokens(context);
        })
        .then(() => {
          return authDelegate.getTokenInfo(context);
        })
        .then((tokenInfo) => {
          return done(null, context.tokenValue, context.refreshTokenValue, tokenInfo);
        })
        .catch((err) => {
          if (err === false) {
            return done(null, false);
          } else {
            err.status = err.status || 401;
            return done(err);
          }
        })
        ;
    }));
  }

  _bindAfterAuthorization(req, res, next) {
    if (this.authDelegate.afterAuthorization) {
      // proxy end()
      var end = res.end;
      res.end = (chunk, encoding) => {
        this.authDelegate.afterAuthorization.call(this.authDelegate, res);
        res.end = end;
        res.end(chunk, encoding);
      }
    }
    next();
  }

  _bindAfterDecision(req, res, next) {
    if (this.authDelegate.afterDecision) {
      // proxy end()
      var end = res.end;
      res.end = (chunk, encoding) => {
        this.authDelegate.afterDecision.call(this.authDelegate, res);
        res.end = end;
        res.end(chunk, encoding);
      }
    }
    next();
  }

  _bindAfterToken(req, res, next) {
    if (this.authDelegate.afterToken) {
      // proxy end()
      var end = res.end;
      res.end = (chunk, encoding) => {
        var data = JSON.parse(chunk);
        this.authDelegate.afterToken.call(this.authDelegate, data, res);
        res.end = end;
        res.end(chunk, encoding);
      }
    }
    next();
  }


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
  getAuthorization() {
    return [
      _.bind(this.authDelegate.ensureLoggedIn, this.authDelegate),
      _.bind(this._bindAfterAuthorization, this),
      this.server.authorization((clientId, redirectUri, done) => {
        this.authDelegate
          .findClient({
            clientId: clientId,
            clientSecret: false
          })
          .then((client) => {
            if (client === false) {
              throw false;
            }
            done(null, client, redirectUri);
          })
          .catch((err) => {
            if (err === false) {
              return done(null, false);
            } else {
              err.status = err.status || 401;
              return done(err);
            }
          })
        ;
      }),
      _.bind(this.authDelegate.approveClient, this.authDelegate)()
    ];
  }

  // user decision endpoint
  //
  // `decision` middleware processes a user's decision to allow or deny access
  // requested by a client application.  Based on the grant type requested by the
  // client, the above grant middleware configured above will be invoked to send
  // a response.
  getDecision() {
    return [
      _.bind(this.authDelegate.ensureLoggedIn, this.authDelegate),
      _.bind(this._bindAfterDecision, this),
      this.server.decision()
    ];
  }

  // token endpoint
  //
  // `token` middleware handles client requests to exchange authorization grants
  // for access tokens.  Based on the grant type being exchanged, the above
  // exchange middleware will be invoked to handle the request.  Clients must
  // authenticate when making requests to this endpoint.
  getToken() {
    return [
      passport.authenticate(['basic', 'oauth2-client-password'], {session: false}),
      _.bind(this._bindAfterToken, this),
      this.server.token(),
      this.server.errorHandler()
    ];
  }
}

OAuth2.passport = passport;

module.exports = OAuth2;
