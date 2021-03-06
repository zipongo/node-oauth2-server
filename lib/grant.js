/**
 * Copyright 2013-present NightWorld.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var auth = require('basic-auth'),
    util = require('util'),
    error = require('./error'),
    runner = require('./runner'),
    GrantBase = require('./grantBase');

module.exports = Grant;


/**
 * Grant
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function Grant (config, req, res, next) {
  GrantBase.call(this, config);
  this.req = req;
  this.res = res;

  /**
   * This is the function order used by the runner
   *
   * @type {Array}
   */
  var fns = [
    extractCredentials,
    this.checkClient,
    exposeClient,
    checkGrantTypeAllowed,
    checkGrantType,
    exposeUser,
    this.generateAccessToken,
    this.saveAccessToken,
    this.generateRefreshToken,
    this.saveRefreshToken,
    sendResponse
  ];
  
  runner(fns, this, next);
}

util.inherits(Grant, GrantBase);

/**
 * Basic request validation and extraction of grant_type and client creds
 *
 * @param  {Function} done
 * @this   OAuth
 */
function extractCredentials (done) {
  // Only POST via application/x-www-form-urlencoded is acceptable
  if (this.req.method !== 'post' ||
      this.req.mime !== 'application/x-www-form-urlencoded') {
    return done(error('invalid_request',
                      'Method must be POST with application/x-www-form-urlencoded encoding'));
  }

  // Grant type
  this.grantType = this.req.payload && this.req.payload.grant_type;
  if (!this.grantType || !this.grantType.match(this.config.regex.grantType)) {
    return done(error('invalid_request',
      'Invalid or missing grant_type parameter'));
  }

  // Extract credentials
  // http://tools.ietf.org/html/rfc6749#section-3.2.1
  this.client = credsFromBasic(this.req) || credsFromBody(this.req);
  if (!this.client.clientId ||
      !this.client.clientId.match(this.config.regex.clientId)) {
    return done(error('invalid_client',
      'Invalid or missing client_id parameter'));
  } else if (!this.client.clientSecret) {
    return done(error('invalid_client', 'Missing client_secret parameter'));
  }

  done();
}

/**
 * Client Object (internal use only)
 *
 * @param {String} id     client_id
 * @param {String} secret client_secret
 */
function Client(id, secret) {
  this.clientId = id;
  this.clientSecret = secret;
}

/**
 * Extract client creds from Basic auth
 *
 * @return {Object} Client
 */
function credsFromBasic (req) {
  var user = auth(req);

  if (!user) return false;

  return new Client(user.name, user.pass);
}

/**
 * Extract client creds from body
 *
 * @return {Object} Client
 */
function credsFromBody (req) {
  return new Client(req.payload.client_id, req.payload.client_secret);
}

/**
 * Delegate to the relvant grant function based on grant_type
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkGrantType (done) {
  if (this.grantType.match(/^[a-zA-Z][a-zA-Z0-9+.-]+:/)
      && this.model.extendedGrant) {
    return useExtendedGrant.call(this, done);
  }

  switch (this.grantType) {
    case 'authorization_code':
      return useAuthCodeGrant.call(this, done);
    case 'password':
      return usePasswordGrant.call(this, done);
    case 'refresh_token':
      return useRefreshTokenGrant.call(this, done);
    case 'client_credentials':
      return useClientCredentialsGrant.call(this, done);
    default:
      done(error('invalid_request',
        'Invalid grant_type parameter or parameter missing'));
  }
}

/**
 * Grant for authorization_code grant type
 *
 * @param  {Function} done
 */
function useAuthCodeGrant (done) {
  var code = this.req.payload.code;

  if (!code) {
    return done(error('invalid_request', 'No "code" parameter'));
  }

  var self = this;
  this.model.getAuthCode(code, function (err, authCode) {
    if (err) return done(error('server_error', false, err));

    if (!authCode || authCode.clientId !== self.client.clientId) {
      return done(error('invalid_grant', 'Invalid code'));
    } else if (authCode.expires < self.now) {
      return done(error('invalid_grant', 'Code has expired'));
    }

    self.user = authCode.user || { id: authCode.userId };
    if (!self.user.id) {
      return done(error('server_error', false,
        'No user/userId parameter returned from getauthCode'));
    }

    done();
  });
}

/**
 * Grant for password grant type
 *
 * @param  {Function} done
 */
function usePasswordGrant (done) {
  // User credentials
  var uname = this.req.payload.username,
    pword = this.req.payload.password;
  if (!uname || !pword) {
    return done(error('invalid_client',
      'Missing parameters. "username" and "password" are required'));
  }

  var self = this;
  return this.model.getUser(uname, pword, function (err, user) {
    if (err) return done(error('server_error', false, err));
    if (!user) {
      return done(error('invalid_grant', 'User credentials are invalid'));
    }

    self.user = user;
    done();
  });
}

/**
 * Grant for refresh_token grant type
 *
 * @param  {Function} done
 */
function useRefreshTokenGrant (done) {
  var token = this.req.payload.refresh_token;

  if (!token) {
    return done(error('invalid_request', 'No "refresh_token" parameter'));
  }

  var self = this;
  this.model.getRefreshToken(token, function (err, refreshToken) {
    if (err) return done(error('server_error', false, err));

    if (!refreshToken || refreshToken.clientId !== self.client.clientId) {
      return done(error('invalid_grant', 'Invalid refresh token'));
    } else if (refreshToken.expires !== null &&
        refreshToken.expires < self.now) {
      return done(error('invalid_grant', 'Refresh token has expired'));
    }

    if (!refreshToken.user && !refreshToken.userId) {
      return done(error('server_error', false,
        'No user/userId parameter returned from getRefreshToken'));
    }

    self.user = refreshToken.user || { id: refreshToken.userId };

    if (self.model.revokeRefreshToken) {
      return self.model.revokeRefreshToken(token, function (err) {
        if (err) return done(error('server_error', false, err));
        done();
      });
    }

    done();
  });
}

/**
 * Grant for client_credentials grant type
 *
 * @param  {Function} done
 */
function useClientCredentialsGrant (done) {
  // Client credentials
  var clientId = this.client.clientId,
    clientSecret = this.client.clientSecret;

  if (!clientId || !clientSecret) {
    return done(error('invalid_client',
      'Missing parameters. "client_id" and "client_secret" are required'));
  }

  var self = this;
  return this.model.getUserFromClient(clientId, clientSecret,
      function (err, user) {
    if (err) return done(error('server_error', false, err));
    if (!user) {
      return done(error('invalid_grant', 'Client credentials are invalid'));
    }

    self.user = user;
    done();
  });
}

/**
 * Grant for extended (http://*) grant type
 *
 * @param  {Function} done
 */
function useExtendedGrant (done) {
  var self = this;
  this.model.extendedGrant(this.grantType, this.req,
      function (err, supported, user) {
    if (err) {
      return done(error(err.type || 'server_error',
        err.description || err.message, err));
    }

    if (!supported) {
      return done(error('invalid_request',
        'Invalid grant_type parameter or parameter missing'));
    } else if (!user || user.id === undefined) {
      return done(error('invalid_request', 'Invalid request.'));
    }

    self.user = user;
    done();
  });
}

/**
 * Check the grant type is allowed for this client
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkGrantTypeAllowed (done) {
  this.model.grantTypeAllowed(this.client.clientId, this.grantType,
      function (err, allowed) {
    if (err) return done(error('server_error', false, err));

    if (!allowed) {
      return done(error('invalid_client',
        'The grant type is unauthorised for this client_id'));
    }

    done();
  });
}

/**
 * Expose user
 *
 * @param  {Function} done
 * @this   OAuth
 */
function exposeUser (done) {
  this.req.app.user = this.user;

  done();
}

function exposeClient (done) {
  this.req.app.oauth = { client: this.clientModel };
  
  done();
}

/**
 * Create an access token and save it with the model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function sendResponse (done) {
  var response = {
    token_type: 'bearer',
    access_token: this.accessToken
  };

  if (this.config.accessTokenLifetime !== null) {
    if (this.config.accessTokenLifetime[this.client.clientId] !== undefined) {
      // Allow custom lifetime per client
      response.expires_in = this.config.accessTokenLifetime[this.client.clientId];
    } else {
      response.expires_in = this.config.accessTokenLifetime;
    }
  }

  if (this.refreshToken) response.refresh_token = this.refreshToken;

  this.res(response)
    .header('Cache-Control', 'no-store')
    .header('Pragma', 'no-cache')
    .type('application/json');

  if (this.config.continueAfterResponse)
    done();
}
