/* global WIKI */

// ------------------------------------
// THU CST Info 9 Account
// ------------------------------------
const OAuth2Strategy = require('passport-oauth2').Strategy

const _ = require('lodash')

module.exports = {
  init (passport, conf) {
    const siteURL = conf.siteURL.slice(-1) === '/' ? conf.siteURL.slice(0, -1) : conf.siteURL

    OAuth2Strategy.prototype.userProfile = function (accessToken, cb) {
      this._oauth2.get(`${siteURL}/api/v2/userinfo`, accessToken, (err, body, res) => {
        if (err) {
          WIKI.logger.warn('THU CST Info 9 - Failed to fetch user profile.')
          return cb(err)
        }
        try {
          const usr = JSON.parse(body).user
          cb(null, {
            id: usr.student_id,
            displayName: _.isEmpty(usr.name) ? usr.fullname : usr.name,
            email: usr.email,
            picture: _.get(usr, 'icon', '')
          })
        } catch (err) {
          WIKI.logger.warn('THU CST Info 9 - Failed to parse user profile.')
          cb(err)
        }
      })
    }

    passport.use('thucst',
      new OAuth2Strategy({
        authorizationURL: `${siteURL}/api/v2/authorize`,
        tokenURL: `${siteURL}/api/v2/access_token`,
        clientID: conf.clientId,
        clientSecret: conf.clientSecret,
        callbackURL: conf.callbackURL,
        passReqToCallback: true
      }, async (req, accessToken, refreshToken, profile, cb) => {
        try {
          const user = await WIKI.models.users.processProfile({
            providerKey: req.params.strategy,
            profile
          })
          cb(null, user)
        } catch (err) {
          cb(err, null)
        }
      })
    )
  },
  logout(conf) {
    if (!conf.logoutURL) {
      return '/'
    } else {
      return conf.logoutURL
    }
  }
}