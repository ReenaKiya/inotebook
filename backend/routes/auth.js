const express = require('express');
const User = require('../models/User')
const router = express.Router()
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var fetchuser = require('../middleware/fetchuser')
const JWT_SECRET = 'Harryisgoodboy';

//ROUTE 1: create a User using:POST"/api/auth/createuser" .No login required
router.post('/createuser', [
  body('name', 'Enter a valid name').isLength({ min: 3 }),
  body('email', 'Enter a valid email').isEmail(),
  body('password', 'password must be atleast 5 characters').isLength({ min: 5 }),
], async (req, res) => {
  let success = false;
  // if there are errors, return bad request and the errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success, errors: errors.array() });
  }
  try {
    // check whether the user with this email exists already
    let user = await User.findOne({ email: req.body.email });
    if (user) {
      return res.status(400).json({ success, error: "sorry a  user with this email already exists" })
    }
    const salt = await bcrypt.genSalt(10)
    const secPass = await bcrypt.hash(req.body.password, salt)

    // creat a new user
    user = await User.create({
      name: req.body.name,
      password: secPass,
      email: req.body.email,
    })
    const data = {
      user: {
        id: user.id
      }
    }

    const authtoken = jwt.sign(data, JWT_SECRET)

    success = true;
    res.json({ success, authtoken })
    // res.json(user)
    // catch errors
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Internal server error")
  }
})


//ROUTE 2: Authenticate a User using:POST"/api/auth/login" .No login required
router.post('/login', [
  body('email', 'Enter a valid email').isEmail(),
  body('password', 'password can not be blank').exists(),
], async (req, res) => {
  let success = false;
  // if there are errors, return bad request and the errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (!user) {
      success = false;
      return res.status(400).json({ error: "please try to login with correct credential" })
    }

    const passwordcompare = await bcrypt.compare(password, user.password)
    if (!passwordcompare) {
      success = false;
      return res.status(400).json({ success, error: "please try to login with correct credential" })
    }
    const data = {
      user: {
        id: user.id
      }
    }
    const authtoken = jwt.sign(data, JWT_SECRET)
    success = true;
    res.json({ success, authtoken })

  } catch (error) {
    console.error(error.message);
    res.status(500).send("Internal server error")
  }
})



//ROUTE 3: Get loggedin User Details Using :POST"/api/auth/getuser"  login required

router.post('/getuser', fetchuser, async (req, res) => {

  try {
    userId = req.user.id
    const user = await User.findById(userId).select("-password");
    res.send(user)
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Internal server error")
  }
})

module.exports = router