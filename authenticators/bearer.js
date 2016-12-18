/**
 * Created by eugenia on 17.12.16.
 */
const Authenticator = require('./authenticator');

class BearerAuthenticator extends Authenticator {
  constructor(options, verify) {
    if (typeof options === 'function') {
      verify = options;
      options = {};
    }

    this.passReqToCallback = options.passReqToCallback;

    super({
      verify,
      name: Authenticator.AUTH_TYPES.BEARER
    });
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
        return this.fail(400);
      }
    }

    if (req.body && req.body.access_token) {
      if (token) {
        return this.fail(400);
      }
      token = req.body.access_token;
    }

    if (req.query && req.query.access_token) {
      if (token) {
        return this.fail(400);
      }
      token = req.query.access_token;
    }

    if (!token) {
      return this.fail(this._challenge());
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
        return this.fail(this._challenge('invalid_token', info.message));
      }

      this.success(user, info);
    }

    if (this.passReqToCallback) {
      this.verify(req, token, callback.bind(this));
    } else {
      this.verify(token, callback.bind(this));
    }
  }
}

module.exports = BearerAuthenticator;