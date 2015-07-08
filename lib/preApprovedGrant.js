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
  error = require('./error'),
  token = require('./token');

module.exports = PreApprovedGrant;

// Runner that allows return values.
function runner (fns, context, next) {
  var last = fns.length - 1;

  (function run(pos) {
    fns[pos].call(context, function (err, response) {
      if (err) return next(err);
      if (pos === last) return next(null, response);
      run(++pos);
    });
  })(0);
}

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [ extractPreApprovedCredentials,
            checkClient,
            checkGrantType,
            generateAccessToken,
            saveAccessToken,
            generateRefreshToken,
            saveRefreshToken,
            returnPreApprovedResponse
          ];

/**
 * Constructor for a pre-approved Grant (allows direct grants of preApproved (sso) users).
 * In-server use only.
 *
 * @param {Object}   config         Instance of OAuth object
 * @param {Object}   preApproved    An Object containing user, client_id, and client_secret properties
 * @param {Function} next           ending callback.  passed (err, response)
 */
function PreApprovedGrant(config, preApproved, next) {
  this.config = config;
  this.model = config.model;
  this.now = new Date();
  this.preApproved = preApproved;
  this.grantType = 'preApproved';
  if (this.config.continueAfterResponse) {
    throw new Error('continueAfterResponse option incompatible to preApproved');
  }
  
  runner(fns, this, next);
}
  
function extractPreApprovedCredentials (done) {
  if (!this.preApproved.user) {
    return done(error('invalid_grant', 'Pre-approved user is missing'));
  }
  
  this.client = new Client(this.preApproved.client_id, this.preApproved.client_secret);
  // XX: share this block.
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
function Client (id, secret) {
  this.clientId = id;
  this.clientSecret = secret;
}

/**
 * Check extracted client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkClient (done) {
  var self = this;
  this.model.getClient(this.client.clientId, this.client.clientSecret,
      function (err, client) {
    if (err) return done(error('server_error', false, err));

    if (!client) {
      return done(error('invalid_client', 'Client credentials are invalid'));
    }

    done();
  });
}

/**
 * Delegate to the relvant grant function based on grant_type
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkGrantType (done) {
  return usePreApprovedGrant.call(this, done);
}

/**
 * Grant for pre-approved grant type
 *
 * @param  {Function} done
 */
function usePreApprovedGrant (done) {
  this.user = this.preApproved.user;
  done();
}

/**
 * Generate an access token
 *
 * @param  {Function} done
 * @this   OAuth
 */
function generateAccessToken (done) {
  var self = this;
  token(this, 'accessToken', function (err, token) {
    self.accessToken = token;
    done(err);
  });
}

/**
 * Save access token with model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function saveAccessToken (done) {
  var accessToken = this.accessToken;

  // Object idicates a reissue
  if (typeof accessToken === 'object' && accessToken.accessToken) {
    this.accessToken = accessToken.accessToken;
    return done();
  }

  var expires = null;
  if (this.config.accessTokenLifetime !== null) {
    expires = new Date(this.now);
    expires.setSeconds(expires.getSeconds() + this.config.accessTokenLifetime);
  }

  this.model.saveAccessToken(accessToken, this.client.clientId, expires,
                             this.user, this.grantType, function (err) {
    if (err) return done(error('server_error', false, err));
    done();
  });
}

/**
 * Generate a refresh token
 *
 * @param  {Function} done
 * @this   OAuth
 */
function generateRefreshToken (done) {
  if (this.config.grants.indexOf('refresh_token') === -1) return done();

  var self = this;
  token(this, 'refreshToken', function (err, token) {
    self.refreshToken = token;
    done(err);
  });
}

/**
 * Save refresh token with model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function saveRefreshToken (done) {
  var refreshToken = this.refreshToken;

  if (!refreshToken) return done();

  // Object idicates a reissue
  if (typeof refreshToken === 'object' && refreshToken.refreshToken) {
    this.refreshToken = refreshToken.refreshToken;
    return done();
  }

  var expires = null;
  if (this.config.refreshTokenLifetime !== null) {
    expires = new Date(this.now);
    expires.setSeconds(expires.getSeconds() + this.config.refreshTokenLifetime);
  }

  this.model.saveRefreshToken(refreshToken, this.client.clientId, expires,
      this.user, function (err) {
    if (err) return done(error('server_error', false, err));
    done();
  });
}

/**
 * Return the response to the runner response
 *
 * @param  {Function} done
 * @this   OAuth
 */
function returnPreApprovedResponse (done) {
  var response = {
    token_type: 'bearer',
    access_token: this.accessToken
  };

  if (this.config.accessTokenLifetime !== null) {
    response.expires_in = this.config.accessTokenLifetime;
  }

  if (this.refreshToken) response.refresh_token = this.refreshToken;
  done(null, response);
}
