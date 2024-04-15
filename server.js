const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const User = require("./models/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

require("dotenv").config();
const cors = require("cors");

const app = express();
app.use(cors());

const port = process.env.PORT || 3000;

app.use(bodyParser.json());

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).send("User created");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).send("User not found");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send("Invalid credentials");
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
