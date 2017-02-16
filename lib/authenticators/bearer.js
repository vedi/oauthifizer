/**
 * Created by eugenia on 17.12.16.
 */

'use strict';

const Authenticator = require('./authenticator');

/**
 * Bearer Authenticator.
 * @constructor
 * @param {object} options - Options. Optional
 * @param {boolean} options.passReqToCallback
 * @param {function} verify - Function for token verification
 */

class BearerAuthenticator extends Authenticator {
  constructor(options, verify) {
    if (typeof options === 'function') {
      verify = options;
      options = {};
    }

    super({
      verify,
      name: Authenticator.AUTH_TYPE.BEARER,
    });

    this.passReqToCallback = options.passReqToCallback;
  }

  /**
   * Authenticate
   * Extracts access token from Authorization header. Writes user model to req[options.userProperty]
   * @function
   * @param {object} req incoming message
   */
  authenticate(req) {
    const { oauthifizerScope } = req;
    let token;

    if (req.headers && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length === 2) {
        const scheme = parts[0];
        const credentials = parts[1];

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        }
      } else {
        return oauthifizerScope.fail(400, 'Invalid bearer token provided');
      }
    }

    if (req.body && req.body.access_token) {
      if (token) {
        return oauthifizerScope.fail(400, 'Multiple tokens provided');
      }
      token = req.body.access_token;
    }

    if (req.query && req.query.access_token) {
      if (token) {
        return oauthifizerScope.fail(400, 'Multiple tokens provided');
      }
      token = req.query.access_token;
    }

    if (!token) {
      return oauthifizerScope.fail(400, 'No token provided');
    }

    function callback(err, user, info = {}) {
      if (err) {
        return oauthifizerScope.error(err);
      }
      if (!user) {
        if (typeof info === 'string') {
          info = { message: info };
        }

        return oauthifizerScope.fail(400, 'invalid_token');
      }

      oauthifizerScope.logIn(user, info);
    }

    if (this.passReqToCallback) {
      this.verify(req, token, callback.bind(this));
    } else {
      this.verify(token, callback.bind(this));
    }
  }
}

module.exports = BearerAuthenticator;
