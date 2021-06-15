const app = require('express')();
const path = require('path');
const session = require('express-session');
const port = 8080;

require('dotenv').config();
const env = process.env;

const passport = require('passport'),
  YandexStrategy = require('passport-yandex').Strategy;
GoogleStrategy = require('passport-google-oauth2').Strategy;

app.use(session({ secret: env.SECRET, resave: true, saveUninitialized: true }));

const fs = require('fs');
const usersList = fs.readFileSync('users.json');
let Users = JSON.parse(usersList);

const findUserByLogin = (login) => {
  return Users.find((element) => {
    return element.login == login;
  });
};

const findUserByEmail = (email) => {
  return Users.find((element) => {
    return element.email.toLowerCase() == email.toLowerCase();
  });
};

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.login);
});

passport.deserializeUser((login, done) => {
  user = findUserByLogin(login);
  done(null, user);
});

passport.use(
  new GoogleStrategy(
    {
      clientID: env.GOOGLE_ID,
      clientSecret: env.GOOGLE_SECRET,
      callbackURL: 'http://localhost:8080/auth/google/callback',
    },
    (_accessToken, _refreshToken, profile, done) => {
      let user = findUserByEmail(profile.emails[0].value);
      user.profile = profile;
      if (user) return done(null, user);

      done(true, null);
    }
  )
);

passport.use(
  new YandexStrategy(
    {
      clientID: env.YANDEX_ID,
      clientSecret: env.YANDEX_SECRET,
      callbackURL: 'http://localhost:8080/auth/yandex/callback',
    },
    (_accessToken, _refreshToken, profile, done) => {
      let user = findUserByEmail(profile.emails[0].value);
      user.profile = profile;
      if (user) return done(null, user);

      done(true, null);
    }
  )
);

const isAuth = (req, res, next) => {
  if (req.isAuthenticated()) return next();

  res.redirect('/sorry');
};

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'main.html'));
});
app.get('/sorry', (_req, res) => {
  res.sendFile(path.join(__dirname, 'sorry.html'));
});
app.get('/auth/yandex', passport.authenticate('yandex'));

app.get(
  '/auth/yandex/callback',
  passport.authenticate('yandex', {
    failureRedirect: '/sorry',
    successRedirect: '/private',
  })
);

app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['email', 'profile'] })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/sorry',
    successRedirect: '/private',
  })
);

app.get('/private', isAuth, (req, res) => {
  res.send(req.user.login);
});

app.get('/logout', isAuth, (req, res) => {
  res.send(req.session.destroy());
});

app.listen(port, () => console.log(`App listening on port ${port}!`));
