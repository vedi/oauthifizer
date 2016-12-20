'use strict';
const url = require('url');
const _ = require('lodash');
const Bb = require('bluebird');

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

    this.grantTypes = {
      PASSWORD: 'password',
      IMPLICIT: 'implicit',
      AUTHORIZATION_CODE: 'authorization_code',
      REFRESH_TOKEN: 'refresh_token'
    };

    /*this.server.grant(oauth2orize.grant.code((client, redirectUri, user, ares, done) => {

      TODO: where to put this?
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
    }));*/

    this.exchangeHandlers = {
      [this.grantTypes.AUTHORIZATION_CODE] (req, res, done) {
        const {user: client} = req;
        const {codeValue, redirectUri} = req.body;
        const context = {
          client,
          codeValue,
          redirectUri,
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
      },
      [this.grantTypes.PASSWORD] (req, res, done) {
        const {user: client} = req;
        const {username, password, scope} = req.body;
        const context = {
          client,
          scope,
          tokenValue: undefined,
          refreshTokenValue: undefined,
          user: undefined
        };

        authDelegate
          .findUser({login: username, password: password})
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
          });
      },
      [this.grantTypes.REFRESH_TOKEN] (req, res, done) {
        const {user: client} = req;
        const {refreshToken, scope} = req.body;
        const context = {
          client,
          scope,
          tokenValue: undefined,
          refreshTokenValue: undefined,
          user: undefined
        };

        return authDelegate
          .findUserByToken({refreshToken})
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
          });
      },
      [this.grantTypes.IMPLICIT] (req, res, done) {
        const {user: client} = req;
        const {
          state,
          scope,
          response_type: responseType,
          redirect_uri: redirectUri
        } = req.body;

        const redirectEndpoint = url.parse(redirectUri);
        const redirectHost = redirectEndpoint.hostname;
        const clientRedirectEndpoint = url.parse(client.redirectUri);
        const clientRedirectHost = clientRedirectEndpoint.hostname;


        if (!responseType) {
          return done({error: 'invalid_request', 'error_description': 'response_type must be specified'});
        }

        if (clientRedirectHost !== redirectHost) {
          return ({error: 'invalid_request', 'error_description': 'Redirect URI mismatch'});
        }

        if (responseType !== 'token') {
          return done({error: 'invalid_request', 'error_description': `Invalid response type "${responseType}"`});
        }

        const token = this.authDelegate.generateTokenValue();

        return this.authDelegate
          .createTokens({
            client,
            tokenValue: token,
            // doesn't need refresh token, userId
            grantType: this.grantTypes.IMPLICIT
          })
          .then(() => {
            let responseRedirectUri = `${redirectUri}?access_token=&token_type=bearer&` +
              `expires_in=${this.authDelegate.tokenLife}`;

            if (state) {
              responseRedirectUri += `&state=${state}`;
            }

            if (scope) {
              responseRedirectUri += `&scope=${scope}`;
            }

            return res.redirect(responseRedirectUri);
          })
          .catch((err) => {
            if (err === false) {
              return done(null, false);
            } else {
              err.status = err.status || 401;
              return done(err);
            }
          });

      }
    };
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

  exchange() {
    return (req, res, next) => {
      const type = req.body['grant_type'];
      const allowedTypes = _.values(this.grantTypes);

      if (!type) {
        return next({error: 'invalid_request', 'error_description': 'Grant type must be specified'});
      }

      if (!allowedTypes.includes(type)) {
        return next({error: 'invalid_grant', 'error_description': `Invalid grant type "${type}"`});
      }

      return this.exchangeHandlers[type](req, res, next);
    }
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
      this.exchange()
    ];
  }


  authenticate(authTypes, options = {}) {
    const {userProperty = 'user'} = options;
    const _this = this;

    if (!Array.isArray(authTypes)) {
      authTypes = [authTypes];
    }

    return (req, res, next) => {

      function endWithFailure() {
        if (options.failureRedirectUrl) {
          return res.redirect(options.failureRedirectUrl);
        }

        return next();
      }


      req.isAuthenticated = () => {
        return !!req[userProperty];
      };

      (function establishAuth(index) {
        if (!authTypes[index]) {
          // all the auths have failed
          return endWithFailure();
        }

        const name = authTypes[index];
        const authenticator = _this._getAuthenticator(name);

        if (!authenticator) {
          throw new Error(`Invalid authentication type ${name}!`);
        }

        authenticator.fail = () => {
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
    };
  }
}

module.exports = OAuth2;
