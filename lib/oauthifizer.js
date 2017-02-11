'use strict';
const url = require('url');
const _ = require('lodash');
const Bb = require('bluebird');

const BasicAuthenticator = require('./authenticators/basic');
const BearerAuthenticator = require('./authenticators/bearer');
const ClientAuthenticator = require('./authenticators/oauth2-client-password');
const { AUTH_TYPE } = require('./authenticators/authenticator');

/**
 * OAuth2.
 * @constructor
 * @param {object} authDelegate - authDelegate
 * @param {boolean} options.passReqToCallback
 * @param {function} verify - Function for token verification
 */
class OAuth2 {
  constructor(authDelegate) {
    this.authDelegate = authDelegate;

    this.authenticators = {
      [AUTH_TYPE.BASIC]: new BasicAuthenticator({ passReqToCallback: true },
        (req, clientId, clientSecret, done) => {
          authDelegate
            .findClient({
              req,
              clientId,
              clientSecret
            })
            .asCallback(done);
        }),
      [AUTH_TYPE.BEARER]: new BearerAuthenticator({ passReqToCallback: true },
        (req, accessToken, done) => {
          return authDelegate
            .findUserByToken({
              req,
              accessToken,
            })
            .then((result) => {
              return done(null, result.obj, result.info);
            })
            .catch((err) => {
              err.status = err.status || 401;
              return done(err);
            });
        }),
      [AUTH_TYPE.CLIENT]: new ClientAuthenticator({ passReqToCallback: true },
        (req, clientId, clientSecret, done) => {
          authDelegate
            .findClient({
              req,
              clientId,
              clientSecret
            })
            .asCallback(done)
        })
    };

    this.GRANT_TYPE = {
      PASSWORD: 'password',
      IMPLICIT: 'implicit',
      AUTHORIZATION_CODE: 'authorization_code',
      REFRESH_TOKEN: 'refresh_token'
    };

    this.exchangeHandlers = {
      [this.GRANT_TYPE.AUTHORIZATION_CODE] (req, res, done) {
        const { user: client } = req;
        const { codeValue, redirectUri } = req.body;
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
            return authDelegate.createAccessToken(context);
          })
          .then((accessToken) => {
            context.tokenValue = accessToken;
            return authDelegate.createRefreshToken(context);
          })
          .then((refreshToken) => {
            context.refreshTokenValue = refreshToken;
            return authDelegate.getTokenInfo(context);
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
      [this.GRANT_TYPE.PASSWORD] (req, res, done) {
        const { user: client } = req;
        const { username, password, scope } = req.body;
        const context = {
          req,
          client,
          scope,
          tokenValue: undefined,
          refreshTokenValue: undefined,
          user: undefined
        };

        authDelegate
          .findUser({ req, login: username, password: password })
          .then((result) => {
            if (result) {
              context.user = result;
              return authDelegate
                .cleanUpTokens(context)
                .then(() => {
                  return authDelegate.createAccessToken(context);
                })
                .then((accessToken) => {
                  context.tokenValue = accessToken;
                  return authDelegate.createRefreshToken(context);
                })
                .then((refreshToken) => {
                  context.refreshTokenValue = refreshToken;
                  return authDelegate.getTokenInfo(context);
                })
                .then((tokenInfo) => {
                  return done(null, context.tokenValue, context.refreshTokenValue, tokenInfo);
                })
            } else {
              return done(null, false);
            }
          })
          .catch((err) => {
            err.status = err.status || 401;
            return done(err);
          });
      },
      [this.GRANT_TYPE.REFRESH_TOKEN] (req, res, done) {
        const { user: client } = req;
        const { refresh_token: refreshToken, scope } = req.body;
        const context = {
          req,
          client,
          scope,
          tokenValue: undefined,
          refreshTokenValue: undefined,
          user: undefined
        };

        return authDelegate
          .findUserByToken({ req, refreshToken })
          .then((result) => {
            if (result.obj !== false) {
              context.user = result.obj;
              return authDelegate
                .cleanUpTokens(context)
                .then(() => {
                  return authDelegate.createAccessToken(context);
                })
                .then((accessToken) => {
                  context.tokenValue = accessToken;
                  return authDelegate.createRefreshToken(context);
                })
                .then((refreshToken) => {
                  context.refreshTokenValue = refreshToken;
                  return authDelegate.getTokenInfo(context);
                })
                .then(() => {
                  return authDelegate.getTokenInfo(context);
                })
                .then((tokenInfo) => {
                  return done(null, context.tokenValue, context.refreshTokenValue, tokenInfo)();
                })
                .catch((err) => {
                  err.status = err.status || 401;
                  return done(err);
                });
            } else {
              return done(null, false);
            }
          });
      },
      [this.GRANT_TYPE.IMPLICIT] (req, res, done) {
        const { user: client } = req;
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
          return done({
            error: 'invalid_request',
            'error_description': 'response_type must be specified'
          });
        }

        if (clientRedirectHost !== redirectHost) {
          return ({ error: 'invalid_request', 'error_description': 'Redirect URI mismatch' });
        }

        if (responseType !== 'token') {
          return done({
            error: 'invalid_request',
            'error_description': `Invalid response type "${responseType}"`
          });
        }

        return this.authDelegate
          .createAccessToken({ req, client })
          .then((token) => {
            let responseRedirectUri = `${redirectUri}?access_token=${token}&token_type=bearer&` +
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

  /**
   * @function
   * @param {string} name - authenticator name. One of AUTH_TYPE
   * @returns authenticator
   * */
  _getAuthenticator(name) {
    return this.authenticators[name];
  }

  /**
   * Exchanges request data to access token depending on grant_type
   * @function
   * */
  exchange() {
    /**
     * @function
     * @param {string} grant_type - Grant, one of this.GRANT_TYPES
     * @param {string} username - For password grant_type only
     * @param {string} password - For password grant_type only
     * @param {string} client_id
     * @param {string} client_secret
     * @param {string} scope - Optional. scope of resources to get access to
     * @param {string} state - For implicit and authorization_code grant types only
     * @param {string} redirect_uri - For implicit and authorization_code grant types only
     * */
    return (req, res, next) => {
      const type = req.body['grant_type'];
      const allowedTypes = _.values(this.GRANT_TYPE);

      if (!type) {
        return next({
          status: 400,
          error: 'invalid_request',
          'error_description': 'Grant type must be specified'
        });
      }

      if (!allowedTypes.includes(type)) {
        return next({
          status: 400,
          error: 'invalid_grant',
          'error_description': `Invalid grant type "${type}"`
        });
      }

      return this.exchangeHandlers[type](req, res, this.respond(res, next));
    }
  }


  /** Sends auth result
   * @function
   * @param {object} res - Incoming message
   * @param {function} next
   * */
  respond(res, next) {

    /**
     * @function
     * @param {object} err
     * @param {string} accessToken
     * @param {string} refreshToken - Optional if grant_type is implicit
     * @param {object} params
     * @returns ends server response
     * */
    return (err, accessToken, refreshToken, params = {}) => {
      if (err) {
        return next(err);
      }
      if (!accessToken) {
        return next({
          status: 400,
          error: 'invalid_grant',
          error_description: 'Invalid resource owner credentials'
        });
      }
      if (refreshToken && typeof refreshToken == 'object') {
        params = refreshToken;
        refreshToken = null;
      }

      const response = { 'expires_in': this.authDelegate.tokenLife };
      response.access_token = accessToken;
      if (refreshToken) {
        response.refresh_token = refreshToken;
      }
      if (params) {
        Object.assign(response, params);
      }
      response.token_type = response.token_type || 'bearer';

      const json = JSON.stringify(response);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.end(json);
    }

  }

  /**
   * token endpoint
   * `token` middleware handles client requests to exchange authorization grants
   * for access tokens.  Based on the grant type being exchanged, the above
   * exchange middleware will be invoked to handle the request.  Clients must
   * authenticate when making requests to this endpoint.
   * */
  getToken() {
    return [
      this.authenticate([AUTH_TYPE.BASIC, AUTH_TYPE.CLIENT]),
      _.bind(this._bindAfterToken, this),
      this.exchange()
    ];
  }

  /**
   * @function
   * Authorization code middleware
   * generates authorization code
   * @returns authorization code
   * */
  getAuthorizationCode() {

    return [
      this.authenticate([AUTH_TYPE.BASIC, AUTH_TYPE.CLIENT]),
      (req, res, done) => {
        const { client, redirectUri, user, ares } = req.body;
        const codeValue = this.authDelegate.generateTokenValue();

        this.authDelegate
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
          });
      }
    ];

  }

  /**
   * @function
   * authenticates request
   * @param {array} authTypes - authentication types. Should be in AUTH_TYPE
   * @param {object} options
   * */

  authenticate(authTypes, options = {}) {
    const { userProperty = 'user' } = options;
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
          return next(err || {
              status: 400,
              message: `Failed to establish ${name} authentication`,
            });
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
