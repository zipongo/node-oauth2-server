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

module.exports = GrantBase;

/**
 * GrantBase abstract base class for grants
 *
 * @param {Object}   config Instance of OAuth object
 */
function GrantBase (config) {
  this.config = config;
  this.model = config.model;
  this.now = new Date();

  // Abstract: this.client
}

/**
 * Check extracted client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
GrantBase.prototype.checkClient = function (done) {
  var self = this;
  this.model.getClient(this.client.clientId,
                       this.client.clientSecret,
                       function (err, client) {
                         if (err) return done(error('server_error', false, err));
                         if (!client) {
                           return done(error('invalid_client', 'Client credentials are invalid'));
                         }
                         this.clientModel = client;
                         done();
                       });
}

/**
 * Generate an access token
 *
 * @param  {Function} done
 * @this   OAuth
 */
GrantBase.prototype.generateAccessToken = function (done) {
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
GrantBase.prototype.saveAccessToken = function (done) {
  var accessToken = this.accessToken;

  // Object idicates a reissue
  if (typeof accessToken === 'object' && accessToken.accessToken) {
    this.accessToken = accessToken.accessToken;
    return done();
  }

  var expires = null,
      lifetime = this.config.accessTokenLifetime;
  if (lifetime[this.client.clientId] !== undefined) {
    // Allow custom lifetime per client
    lifetime = lifetime[this.client.clientId];
  }
  if (lifetime !== null) {
    expires = new Date(this.now);
    expires.setSeconds(expires.getSeconds() + lifetime);
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
GrantBase.prototype.generateRefreshToken = function (done) {
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
GrantBase.prototype.saveRefreshToken = function (done) {
  var refreshToken = this.refreshToken;

  if (!refreshToken) return done();

  // Object idicates a reissue
  if (typeof refreshToken === 'object' && refreshToken.refreshToken) {
    this.refreshToken = refreshToken.refreshToken;
    return done();
  }

  var expires = null,
      lifetime = this.config.refreshTokenLifetime;
  if (lifetime[this.client.clientId] !== undefined) {
    // Allow custom lifetime per client
    lifetime = lifetime[this.client.clientId];
  }
  if (lifetime !== null) {
    expires = new Date(this.now);
    expires.setSeconds(expires.getSeconds() + lifetime);
  }

  this.model.saveRefreshToken(refreshToken, this.client.clientId, expires,
                              this.user, function (err) {
                                if (err) return done(error('server_error', false, err));
                                done();
                              });
}

