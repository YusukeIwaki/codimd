'use strict'

const Router = require('express').Router
const request = require('request')
const passport = require('passport')
const GithubStrategy = require('passport-github').Strategy
const { InternalOAuthError } = require('passport-oauth2')
const config = require('../../config')
const response = require('../../response')
const { setReturnToFromReferer, passportGeneralCallback } = require('../utils')
const { URL } = require('url')
const { promisify } = require('util')

const rp = promisify(request)

const githubAuth = module.exports = Router()

function githubUrl (path) {
  return config.github.enterpriseURL && new URL(path, config.github.enterpriseURL).toString()
}

const scope = [...config.github.scopes]
if (config.github.organizations.length > 0) {
  scope.push('read:org')
}
if (config.allowedEmailDomains.length > 0) {
  scope.push('user:email')
}

passport.use(new GithubStrategy({
  scope,
  clientID: config.github.clientID,
  clientSecret: config.github.clientSecret,
  callbackURL: config.serverURL + '/auth/github/callback',
  authorizationURL: githubUrl('login/oauth/authorize'),
  tokenURL: githubUrl('login/oauth/access_token'),
  userProfileURL: githubUrl('api/v3/user')
}, async (accessToken, refreshToken, profile, done) => {
  if (config.allowedEmailDomains.length > 0) {
    const { statusCode, body: data } = await rp({
      url: `https://api.github.com/user/emails`,
      method: 'GET',
      json: true,
      timeout: 2000,
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'nodejs-http'
      }
    })
    if (statusCode !== 200) {
      return done(InternalOAuthError(
        `Failed to query email for user: ${profile.username}`
      ))
    }
    let ok = false
    for (const { email, verified } of data) {
      if (verified && config.allowedEmailDomains.includes(email.split('@')[1])) {
        ok = true
        break
      }
    }
    if (!ok) {
      return done(InternalOAuthError(
        `User email not whitelisted: ${profile.username} (${data.map(({ email }) => email).join(',')})`
      ))
    }
  }

  if (config.github.organizations.length > 0) {
    const { statusCode, body: data } = await rp({
      url: `https://api.github.com/user/orgs`,
      method: 'GET',
      json: true,
      timeout: 2000,
      headers: {
        Authorization: `token ${accessToken}`,
        'User-Agent': 'nodejs-http'
      }
    })
    if (statusCode !== 200) {
      return done(InternalOAuthError(
        `Failed to query organizations for user: ${profile.username}`
      ))
    }
    let ok = false
    const orgs = data.map(({ login }) => login)
    for (const org of orgs) {
      if (config.github.organizations.includes(org)) {
        ok = true
        break
      }
    }
    if (!ok) {
      return done(InternalOAuthError(
        `User orgs not whitelisted: ${profile.username} (${orgs.join(',')})`
      ))
    }
  }

  return passportGeneralCallback(accessToken, refreshToken, profile, done)
}))

githubAuth.get('/auth/github', function (req, res, next) {
  setReturnToFromReferer(req)
  passport.authenticate('github')(req, res, next)
})

githubAuth.get('/auth/github/callback',
  passport.authenticate('github', {
    successReturnToOrRedirect: config.serverURL + '/',
    failureRedirect: config.serverURL + '/'
  })
)

// github callback actions
githubAuth.get('/auth/github/callback/:noteId/:action', response.githubActions)
