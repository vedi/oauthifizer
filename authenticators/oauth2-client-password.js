/**
 * Created by eugenia on 17.12.16.
 */
const HTTP_STATUSES = require('http-statuses');
const Authenticator = require('./authenticator');

class ClientAuthenticator extends Authenticator {
  constructor(options, verify) {
    if (typeof options === 'function') {
      verify = options;
      options = {};
    }

    super({
      verify,
      name: Authenticator.AUTH_TYPES.CLIENT
    });

    this.passReqToCallback = options.passReqToCallback;
  }

  authenticate(req) {
    if (!req.body || (!req.body['client_id'] || !req.body['client_secret'])) {
      return this.fail();
    }

    const clientId = req.body['client_id'];
    const clientSecret = req.body['client_secret'];

    function callback(err, client, info) {
      if (err) {
        return this.error(err);
      }

      if (!client) {
        return this.fail(HTTP_STATUSES.UNAUTHORIZED.code, HTTP_STATUSES.UNAUTHORIZED.message);
      }

      this.logIn(client, info);
    }

    if (this.passReqToCallback) {
      return this.verify(req, clientId, clientSecret, callback.bind(this));
    } else {
      return this.verify(clientId, clientSecret, callback.bind(this));
    }
  }
}

module.exports = ClientAuthenticator;