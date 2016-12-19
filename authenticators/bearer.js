/**
 * Created by eugenia on 17.12.16.
 */
const HTTP_STATUSES = require('http-statuses');
const Authenticator = require('./authenticator');

class BearerAuthenticator extends Authenticator {
  constructor(options, verify) {
    if (typeof options === 'function') {
      verify = options;
      options = {};
    }

    super({
      verify,
      name: Authenticator.AUTH_TYPES.BEARER
    });

    this.passReqToCallback = options.passReqToCallback;
  }

  authenticate(req) {
    let token;

    if (req.headers && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length == 2) {
        const scheme = parts[0];
        const credentials = parts[1];

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        }
      } else {
        return this.fail(HTTP_STATUSES.BAD_REQUEST.code, 'Invalid bearer token provided');
      }
    }

    if (req.body && req.body.access_token) {
      if (token) {
        return this.fail(HTTP_STATUSES.BAD_REQUEST.code, 'Multiple tokens provided');
      }
      token = req.body.access_token;
    }

    if (req.query && req.query.access_token) {
      if (token) {
        return this.fail(HTTP_STATUSES.BAD_REQUEST.code, 'Multiple tokens provided');
      }
      token = req.query.access_token;
    }

    if (!token) {
      return this.fail(HTTP_STATUSES.BAD_REQUEST.code, 'No token provided');
    }

    function callback(err, user, info) {
      if (err) {
        return this.error(err);
      }
      if (!user) {
        if (typeof info == 'string') {
          info = {message: info}
        }
        info = info || {};
        // TODO: set proper errors as specified in oauth2.0 specs
        return this.fail(HTTP_STATUSES.BAD_REQUEST.code, 'invalid_token');
      }

      this.logIn(user, info);
    }

    if (this.passReqToCallback) {
      this.verify(req, token, callback.bind(this));
    } else {
      this.verify(token, callback.bind(this));
    }
  }
}

module.exports = BearerAuthenticator;