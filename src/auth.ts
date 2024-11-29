import express, {Request} from 'express'
import passport from 'passport'
import { GoogleCallbackParameters, Strategy as GoogleStrategy, VerifyCallback } from 'passport-google-oauth20'
import { Strategy as FacebookStrategy, VerifyFunction } from 'passport-facebook'
import { Strategy as TwitterStrategy } from 'passport-twitter'
import { sqlQuest } from './db'

// Federated Provision function to check or create a user
function federatedProvision(provider: string, profile: passport.Profile, cb: Function) {
  // Check if there's already a federated login linked to a user
  sqlQuest
    .oneOrNone(
      'SELECT * FROM federated_credentials WHERE provider = $1 AND subject = $2',
      [provider, profile.id]
    )
    .then(async (row) => {
      if (row) {
        // If a federated login exists, find the associated user
        try {
          const user = await sqlQuest.one(
            'SELECT * FROM "user" WHERE id = $1',
            [row.user_id]
          )
          return cb(null, user)
        } catch (err) {
          return cb(err)
        }
      } else {
        // If no federated login exists, create a new user
        try {
          await sqlQuest.none(
            'INSERT INTO "user" ("username", "name") VALUES ($1, $2)',
            [profile.id, profile.displayName]
          )
          try {
            const user_1 = await sqlQuest.one(
              'SELECT * FROM "user" WHERE username = $1',
              [profile.id]
            )
            await sqlQuest.none(
              'INSERT INTO federated_credentials (user_id, provider, subject) VALUES ($1, $2, $3)',
              [user_1.id, provider, profile.id]
            )
            return cb(null, user_1)
          } catch (err_1) {
            return cb(err_1)
          }
        } catch (err_2) {
          return cb(err_2)
        }
      }
    })
    .catch((err) => cb(err))
}

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env['GOOGLE_CLIENT_ID'] as string,
      clientSecret: process.env['GOOGLE_CLIENT_SECRET'] as string,
      callbackURL: 'http://localhost:4000/auth/google/callback',
      scope: ['profile'],
      passReqToCallback:true,
    },
    function verify(req: Request,
        accessToken: string,
        refreshToken: string,
        params: GoogleCallbackParameters, 
        profile: passport.Profile, 
        cb: VerifyCallback) {
      return federatedProvision('google', profile, cb)
    }
  )
)

// Facebook OAuth Strategy
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env['FACEBOOK_CLIENT_ID'] as string,
      clientSecret: process.env['FACEBOOK_CLIENT_SECRET'] as string,
      callbackURL: '/oauth2/redirect/facebook', // Consider using process.env.FACEBOOK_CALLBACK_URL
      state: true,
    },
    function verify(accessToken, refreshToken, profile: passport.Profile, cb: VerifyFunction) {
      return federatedProvision('facebook', profile, cb)
    }
  )
)

// Twitter OAuth Strategy
passport.use(
  new TwitterStrategy(
    {
      consumerKey: process.env['TWITTER_CONSUMER_KEY'] as string,
      consumerSecret: process.env['TWITTER_CONSUMER_SECRET'] as string,
      callbackURL: '/oauth/callback/twitter', // Consider using process.env.TWITTER_CALLBACK_URL
    },
    function verify(token, tokenSecret, profile, cb) {
      return federatedProvision('twitter', profile, cb)
    }
  )
)

// Serialize the user to the session
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, user)
  })
})

// Deserialize the user from the session
passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {user})
  })
})

// Router setup
const router = express.Router()

// Federated login routes
router.get('/login', (req, res, next) => {
  res.render('login')
})

// Google login route
router.get('/login/federated/google', passport.authenticate('google'))

// Callback after Google authentication
router.get(
  '/oauth2/redirect/google',
  passport.authenticate('google', {
    successReturnToOrRedirect: '/',
    failureRedirect: '/login',
  })
)

// Facebook login route
router.get('/login/federated/facebook', passport.authenticate('facebook'))

// Callback after Facebook authentication
router.get(
  '/oauth2/redirect/facebook',
  passport.authenticate('facebook', {
    successReturnToOrRedirect: '/',
    failureRedirect: '/login',
  })
)

// Twitter login route
router.get('/login/federated/twitter', passport.authenticate('twitter'))

// Callback after Twitter authentication
router.get(
  '/oauth/callback/twitter',
  passport.authenticate('twitter', {
    successReturnToOrRedirect: '/',
    failureRedirect: '/login',
  })
)

// Logout route
router.post('/logout', function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err)
    }
    res.redirect('/')
  })
})

export default router
