import express, { Request, Response, NextFunction } from 'express'
import passport from 'passport'
import { Strategy as LocalStrategy } from 'passport-local'
import bcrypt from 'bcryptjs'
import { sqlQuest } from './db'

passport.use(
  new LocalStrategy(function verify(username: string, password: string, cb) {
    sqlQuest
      .oneOrNone(`SELECT * FROM "user" WHERE "username" = $1`, [username])
      .then((user) => {
        if (!user) {
          return cb(null, false, { message: 'Username not found' })
        }

        bcrypt.compare(password, user.password, function (err, isMatch) {
          if (err) return cb(err)
          if (!isMatch)
            return cb(null, false, { message: 'Incorrect password' })
          return cb(null, user)
        })
      })
      .catch((err) => {
        console.error('Database query error:', err)
        return cb(err)
      })
  })
)

passport.serializeUser(function (user, done) {
  done(null, user)
})

passport.deserializeUser(function (id, done) {
  done(null, { id })
})

const router = express.Router()

// router.get('/login', function(req, res,next){
//     res.json
// })

router.post(
  '/login/password',
  passport.authenticate('local', {
    successReturnToOrRedirect: '/',
    failureRedirect: '/login',
    failureMessage: true,
  })
)

router.post(
  '/register',
  async (req: Request, res: Response, next: NextFunction): Promise<any> => {
    try {
      const existingUser = await sqlQuest.oneOrNone(
        'SELECT * FROM "user" WHERE "username" = $1',
        [req.body.username]
      )

      if (existingUser) {
        return res.status(400).json({ message: 'Username already exists' })
      }

      const hashedPassword = await bcrypt.hash(req.body.password, 12)

      await sqlQuest.none(
        'INSERT INTO "user" ("username", "password") VALUES ($1, $2)',
        [req.body.username, hashedPassword]
      )

      return res.status(201).json({ message: 'User registered successfully' })
    } catch (error) {
      console.error('Error registering user:', error)
      return res
        .status(500)
        .json({ message: 'Internal server error', error: 'error' })
    }
  }
)

/* POST /logout
 *
 * This route logs the user out.
 */
router.post('/logout', function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err)
    }
    res.redirect('/')
  })
})

export default router
