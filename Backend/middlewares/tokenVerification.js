const createHttpError = require("http-errors");
const jwt = require("jsonwebtoken");
const config = require("../config/config");
const User = require("../models/userModel");

const isVerifiedUser = async (req, res, next) => {
  try {
    const token = req.cookies.accessToken;

    if (!token) {
      return next(createHttpError(401, "Access token not provided!"));
    }

    const decoded = jwt.verify(token, config.accessTokenSecret);
    const user = await User.findById(decoded._id).select("-password");

    if (!user) {
      return next(createHttpError(401, "User does not exist!"));
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("Token verification error:", error);
    next(createHttpError(401, "Invalid or expired token!"));
  }
};

module.exports = { isVerifiedUser };
