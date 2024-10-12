import User from "../models/user.model.js"
import { errorHandler } from "../utils/error.js"
import bcryptjs from "bcryptjs"
import jwt from "jsonwebtoken"

export const signup = async (req, res, next) => {
  const { username, email, password } = req.body;

  try {
    const isValidUser = await User.findOne({ email });

    if (isValidUser) {
      return next(errorHandler(400, "User already exists"));
    }

    const hashedPassword = bcryptjs.hashSync(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({
      success: true,
      message: "User Created Successfully",
    });
  } catch (error) {
    console.error("Signup error:", error);
    next(error);
  }
};


export const signin = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    console.log("Looking for user with email:", email);
    const validUser = await User.findOne({ email });

    if (!validUser) {
      console.log("User not found");
      return next(errorHandler(404, "User not found"));
    }

    console.log("Comparing passwords");
    const validPassword = bcryptjs.compareSync(password, validUser.password);

    if (!validPassword) {
      console.log("Invalid password");
      return next(errorHandler(401, "Wrong Credentials"));
    }

    console.log("Generating JWT token");
    const token = jwt.sign({ id: validUser._id }, process.env.JWT_SECRET);

    const { password: pass, ...rest } = validUser._doc;

    console.log("Sending response");
    res.cookie("access_token", token, { httpOnly: true }).status(200).json({
      success: true,
      message: "Login Successful!",
      rest,
    });
  } catch (error) {
    console.error("Signin error:", error);
    next(error);
  }
};

export const signout = async (req, res, next) => {
  try {
    res.clearCookie("access_token");

    res.status(200).json({
      success: true,
      message: "User logged out successfully",
    });
  } catch (error) {
    console.error("Signout error:", error);
    next(error);
  }
};
