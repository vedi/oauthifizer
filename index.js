'use strict';

const _ = require('lodash');
const Bb = require('bluebird');
const HTTP_STATUSES = require('http-statuses');
const oauth2orize = require('oauth2orize');

const BasicAuthenticator = require('./authenticators/basic');
const BearerAuthenticator = require('./authenticators/bearer');
const ClientAuthenticator = require('./authenticators/oauth2-client-password');
const {AUTH_TYPES} = require('./authenticators/authenticator');

class OAuth2 {

  constructor(authDelegate) {
    this.authDelegate = authDelegate;

    this.authenticators = {
      [AUTH_TYPES.BASIC]: new BasicAuthenticator((clientId, clientSecret, done) => {
        authDelegate
          .findClient({
            clientId,
            clientSecret
          })
          .asCallback(done)
        ;
      }),
      [AUTH_TYPES.BEARER]: new BearerAuthenticator((accessToken, done) => {
        return authDelegate
          .findUserByToken({accessToken})
          .then((result) => {
            return done(null, result.obj, result.info)
          })
          .catch((err) => {
            err.status = err.status || 401;
            return done(err);
          })
          ;
      }),
      [AUTH_TYPES.CLIENT]: new ClientAuthenticator((clientId, clientSecret, done) => {
        authDelegate
          .findClient({
            clientId,
            clientSecret
          })
          .asCallback(done)
      })
    };

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
      const codeValue = authDelegate.generateTokenValue();

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
      const context = {
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
      const context = {
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
      const context = {
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
      const end = res.end;
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
      const end = res.end;
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
      const end = res.end;
      res.end = (chunk, encoding) => {
        const data = JSON.parse(chunk);
        this.authDelegate.afterToken.call(this.authDelegate, data, res);
        res.end = end;
        res.end(chunk, encoding);
      }
    }
    next();
  }

  _getAuthenticator(name) {
    return this.authenticators[name];
  }

  // user authorization endpoint
  //
  // `authorization` middleware accepts a `validate` callback which is
  // responsible for validating the client making the authorization request.  In
  // doing so, is recommended that the `redirectURI` be checked against a
  // registered value, although security requirements may vary across
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
      this.authenticate([AUTH_TYPES.BASIC, AUTH_TYPES.CLIENT]),
      _.bind(this._bindAfterToken, this),
      this.server.token(),
      this.server.errorHandler()
    ];
  }

  authenticate(authTypes, options = {}) {
    const failures = [];
    const {userProperty = 'user'} = options;

    if (!Array.isArray(authTypes)) {
      authTypes = [authTypes];
    }

    return (req, res, next) => {

      function endWithFailure() {
        if (options.failureRedirectUrl) {
          return res.redirect(options.failureRedirectUrl);
        }

        if (options.failWithMessage) {
          let status = HTTP_STATUSES.UNAUTHORIZED.code;

          _.forEach(HTTP_STATUSES, (item) => {
            if (item.code === failures[0].code) {
              status = item;
            }
          });

          return next(status.createError(failures[0].message));
        }

        return res.end(failures[0].code, failures[0].message);
      }


      req.isAuthenticated = () => {
        return !!req[userProperty];
      };

      (function establishAuth(index) {
        if (!authTypes[index]) {
          // all auths have failed
          return endWithFailure();
        }

        const name = authTypes[index];
        const authenticator = this._getAuthenticator(name);

        if (!authenticator) {
          throw new Error(`Invalid authentication type ${name}!`);
        }

        authenticator.fail = (code, message) => {
          failures.push({code, message});
          return establishAuth(index + 1);
        };

        authenticator.error = (err) => {
          return next(err || {message: `Failed to establish ${name} authentication`});
        };

        authenticator.logIn = (user) => {
          req[userProperty] = user;

          if (options.successRedirectUrl) {
            return res.redirect(options.successRedirectUrl);
          }

          return next();
        };

        return authenticator.authenticate(req);

      })(0);


      next();
    };
  }
}

module.exports = OAuth2;
