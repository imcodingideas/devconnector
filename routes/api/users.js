const express = require('express')
const gravatar = require('gravatar')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../../models/User')
const keys = require('../../config/keys')

const router = express.Router()

// @route   GET api/users/test
// @desc    Tests users route
// @access  Public
router.get('/test', (req, res) => res.json({ msg: 'Users Works' }))

// @route   GET api/users/register
// @desc    Register users
// @access  Public
router.post('/register', (req, res) => {
  const { email, name, password } = req.body

  User.findOne({ email }).then(user => {
    if (user) {
      return res.status(400).json({ email: 'Email already exists' })
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
  const { email, password } = req.body

  User.findOne({ email }).then(user => {
    if (!user) {
      return res.status(404).json({ email: 'User not found' })
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
        return res.status(400).json({ password: 'Password incorrect' })
      }
    })
  })
})

module.exports = router
