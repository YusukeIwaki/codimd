'use strict'

const Router = require('express').Router
const request = require('request')
const passport = require('passport')
const BitbucketStrategy = require('passport-bitbucket-oauth2').Strategy
const { InternalOAuthError } = require('passport-oauth2')
const config = require('../../config')
const { setReturnToFromReferer, passportGeneralCallback } = require('../utils')
const { promisify } = require('util')

const rp = promisify(request)

const bitbucketAuth = module.exports = Router()

passport.use(new BitbucketStrategy({
  clientID: config.bitbucket.clientID,
  clientSecret: config.bitbucket.clientSecret,
  callbackURL: config.serverURL + '/auth/bitbucket/callback'
}, async (accessToken, refreshToken, profile, done) => {
  if (config.allowedEmailDomains.length > 0) {
    const { statusCode, body: data } = await rp({
      url: `https://api.bitbucket.org/2.0/user/emails`,
      method: 'GET',
      json: true,
      timeout: 2000,
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'User-Agent': 'nodejs-http'
      }
    })

    if (statusCode !== 200) {
      return done(InternalOAuthError(
        `Failed to query email for user: ${profile.username}`
      ))
    }

    let ok = false
    for (const { email, is_confirmed } of data.values) {
      if (is_confirmed && config.allowedEmailDomains.includes(email.split('@')[1])) {
        ok = true
        break
      }
    }
    if (!ok) {
      return done(InternalOAuthError(
        `User email not in allowed domains: ${profile.username}`
      ))
    }
  }

  return passportGeneralCallback(accessToken, refreshToken, profile, done)
}))

bitbucketAuth.get('/auth/bitbucket', function (req, res, next) {
  setReturnToFromReferer(req)
  passport.authenticate('bitbucket')(req, res, next)
})

// bitbucket auth callback
bitbucketAuth.get('/auth/bitbucket/callback',
  passport.authenticate('bitbucket', {
    successReturnToOrRedirect: config.serverURL + '/',
    failureRedirect: config.serverURL + '/'
  })
)
