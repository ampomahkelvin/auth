import express, { Express, Request, Response } from 'express'
import session from 'express-session'
import http from 'http'
import cors from 'cors'
import dotenv from 'dotenv'
import { connectDB } from './db'
import router from './localStrategyAuth'
import authRouter from './auth'
import passport from 'passport'

dotenv.config()

async function main(App: (...args: any[]) => Express) {
  await connectDB()

  const app = App()

  const server = http.createServer(app)

  const PORT = process.env.PORT || 8080

  server.on('listening', () => {
    console.log(`listening on http://localhost:${PORT}`)
  })

  server.listen(PORT)
}

export default function App(): Express {
  const app = express()

  const corsOptions = {
    origin: '*',
    credentials: true,
  }

  app.use(cors(corsOptions))
  app.use(express.json())
  app.use(express.urlencoded({ extended: true }))
  app.use(session({
    secret: 'keyboard cat',
    resave: false, // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
  }));
  app.use(passport.authenticate('session'));

  app.use('/auth', router)
  app.use('/auth', authRouter)

  app.get('/', (_: Request, res: Response) => {
    res.send('Project Express + TypeScript Server')
  })
  return app
}

main(App).catch((error) => {
  console.error('Error starting the app:', error)
  process.exit(1)
})
