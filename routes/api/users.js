const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const key = require('../../config/keys').secret;
const User = require('../../model/User');

/**
 * @route POST /api/users/register
 * @description Register User
 * @access Public
 */

router.post('/register', (req, res) => {
  const { username, name, email, password, confirm_password } = req.body;

  if (password != confirm_password) {
    return res.status(400).json({
      msg: 'Password is not match',
    });
  }

  // Check unique username
  User.findOne({
    username,
  })
    .then((user) => {
      if (user) {
        return res.status(400).json({
          msg: 'Username is already registered!',
        });
      }
    })
    .catch((error) => {
      console.log('error: ', error);
      return res.status(500).json({
        error: 'Server error!',
      });
    });

  // Check unique email
  User.findOne({
    email,
  })
    .then((user) => {
      if (user) {
        return res.status(400).json({
          msg: 'Email is already registered!',
        });
      }
    })
    .catch((error) => {
      return res.send(error);
    });

  // The data is valid and user can register this infomations
  let newUser = new User({
    name,
    username,
    email,
    password,
  });

  // Hash password
  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(newUser.password, salt, (err, hash) => {
      if (err) throw err;
      newUser.password = hash;
      newUser
        .save()
        .then((user) => {
          return res.status(201).json({
            success: true,
            msg: 'User is now registered.',
          });
        })
        .catch((error) => {
          console.log('error: ', error);
          return res.send(error)
        });
    });
  });
});

/**
 * @route POST /api/users/login
 * @description login User
 * @access Public
 */

router.post('/login', (req, res) => {
  const { username, password } = req.body;

  User.findOne({ username }).then((user) => {
    if (!user) {
      return res.status(404).json({
        msg: 'Username is not found!',
        success: false,
      });
    }

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        return res.status(400).json({ error: err });
      }

      if (!result) {
        return res.status(400).json({
          msg: 'Incorrect password!',
          success: false,
        });
      }

      const payload = {
        _id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
      };

      jwt.sign(payload, key, { expiresIn: 604800 }, (err, token) => {
        if (err) throw err;

        return res.status(200).json({
          success: true,
          token: `Bearer ${token}`,
          user,
          msg: 'Logged in success',
        });
      });
    });
  });
});

/**
 * @route POST /api/users/profile
 * @description return user data
 * @access Private
 */

router.get(
  '/profile',
  passport.authenticate('jwt', {
    session: false,
  }),
  (req, res) => {
    const user = req.user.toObject();
    delete user.password;

    res.json({ user });
  },
);

module.exports = router;
