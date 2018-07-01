const express = require('express')
const gravatar = require('gravatar')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const passport = require('passport')
const User = require('../../models/User')
const keys = require('../../config/keys')

const validateRegisterInput = require('../../validations/register')
const validateLoginInput = require('../../validations/login')

const router = express.Router()

// @route   GET api/users/test
// @desc    Tests users route
// @access  Public
router.get('/test', (req, res) => res.json({ msg: 'Users Works' }))

// @route   GET api/users/register
// @desc    Register users
// @access  Public
router.post('/register', (req, res) => {
  const { errors, isValid } = validateRegisterInput(req.body)
  const { email, name, password } = req.body

  // Check validation
  if (!isValid) {
    return res.status(400).json(errors)
  }

  User.findOne({ email }).then(user => {
    if (user) {
      errors.email = 'Email already exists'
      return res.status(400).json(errors)
    }
    const avatar = gravatar.url(req.body.email, {
      s: '200',
      r: 'pg',
      d: 'mm',
    })

    const newUser = new User({
      name,
      email,
      avatar,
      password,
    })

    bcrypt.genSalt(10, (err, salt) => {
      bcrypt.hash(newUser.password, salt, (err, hash) => {
        if (err) throw err
        newUser.password = hash
        newUser
          .save()
          .then(user => res.json(user))
          .catch(err => console.log(err))
      })
    })
  })
})

// @route   GET api/users/login
// @desc    Login user / Returning JTW
// @access  Public
router.post('/login', (req, res) => {
  const { errors, isValid } = validateLoginInput(req.body)
  const { email, password } = req.body

  // Check validation
  if (!isValid) {
    return res.status(400).json(errors)
  }

  User.findOne({ email }).then(user => {
    if (!user) {
      errors.email = 'User not found'
      return res.status(404).json(errors)
    }

    bcrypt.compare(password, user.password).then(isMatch => {
      if (isMatch) {
        const payload = {
          id: user.id,
          name: user.name,
          avatar: user.avatar,
        } // JWT Payload

        // sign token
        jwt.sign(
          payload,
          keys.secretOrKey,
          { expiresIn: 3600 },
          (err, token) => {
            res.json({
              success: true,
              token: `Bearer ${token}`,
            })
          }
        )
      } else {
        errors.password = 'Password incorrect'
        return res.status(400).json(errors)
      }
    })
  })
})

// @route   GET api/users/current
// @desc    Return current user
// @access  Private
router.get(
  '/current',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    const { id, name, email } = req.user
    res.json({
      id,
      name,
      email,
    })
  }
)

module.exports = router
