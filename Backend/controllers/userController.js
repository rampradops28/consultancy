const createHttpError = require("http-errors");
const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const config = require("../config/config");

const register = async (req, res, next) => {
  try {
    const { name, phone, email, password, role } = req.body;

    if (!name || !phone || !email || !password || !role) {
      return next(createHttpError(400, "All fields are required!"));
    }

    const isUserPresent = await User.findOne({ email });
    if (isUserPresent) {
      return next(createHttpError(400, "User already exists!"));
    }

    const newUser = new User({ name, phone, email, password, role });
    await newUser.save();

    res.status(201).json({
      success: true,
      message: "New user created!",
      data: newUser,
    });
  } catch (error) {
    next(error);
  }
};

const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return next(createHttpError(400, "All fields are required!"));
    }

    const user = await User.findOne({ email });
    if (!user) {
      return next(createHttpError(401, "Invalid credentials"));
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return next(createHttpError(401, "Invalid credentials"));
    }

    const token = jwt.sign({ _id: user._id }, config.accessTokenSecret, {
      expiresIn: "1d",
    });

    res.cookie("accessToken", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // use HTTPS in production
      sameSite: "None", // required for cross-site cookies
      maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
    });

    res.status(200).json({
      success: true,
      message: "User logged in successfully!",
      data: user,
    });
  } catch (error) {
    next(error);
  }
};

const getUserData = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select("-password");
    if (!user) {
      return next(createHttpError(404, "User not found"));
    }

    res.status(200).json({ success: true, data: user });
  } catch (error) {
    next(error);
  }
};

const logout = (req, res, next) => {
  try {
    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "None",
    });

    res.status(200).json({ success: true, message: "User logged out successfully!" });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  register,
  login,
  getUserData,
  logout,
};
