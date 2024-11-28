import asyncHandler from "express-async-handler";
import User from "../models/userModel.js";
import bcrypt from "bcryptjs";
import parser from "ua-parser-js";
import { generateToken, hashToken } from "../utils/index.js";
import jwt from "jsonwebtoken";
import { sendEmail } from "../utils/sendEmail.js";
import Token from "../models/tokenModel.js";
import crypto from "crypto";
import Cryptr from "cryptr";
import dotenv from "dotenv";
import { OAuth2Client } from "google-auth-library";

dotenv.config();

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const cryptr = new Cryptr(process.env.CRYPTR_KEY);

const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;
  console.log(username, email, password);
  //Validation
  if (!username || !email || !password) {
    res.status(400);
    throw new Error("Please fill in all the required fields!");
  }

  if (password.length < 6) {
    res.status(400);
    throw new Error("Password must be more than 6 characters");
  }

  // Check if the user exists
  const userExistsByUsername = await User.findOne({ username });
  const userExistsByEmail = await User.findOne({ email });
  if (userExistsByUsername || userExistsByEmail) {
    res.status(400);
    throw new Error("User already exist");
  }

  //Get UserAgent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  //Create new User
  const user = await User.create({
    username,
    email,
    password,
    userAgent,
  });

  //Generate the Token
  const token = generateToken(user._id);

  //Send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), //1 day
    sameSite: "none",
    secure: true,
  });

  if (user) {
    const { _id, username, email, phone, bio, photo, role, isVerified } = user;
    res.status(201).json({
      _id,
      username,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
});

const loginUser = asyncHandler(async (req, res) => {
  const { username, password } = req.body;

  //Validate
  if (!username || !password) {
    res.status(400);
    throw new Error("Please add username and password");
  }

  const user = await User.findOne({ username });

  if (!user) {
    res.status(404);
    throw new Error("User not found, please sign up");
  }

  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  if (!passwordIsCorrect) {
    res.status(400);
    throw new Error("Invalid email or password");
  }

  // Trigger 2FA for unkown UserAgent
  const ua = parser(req.headers["user-agent"]);
  const thisUserAgent = ua.ua;
  console.log(thisUserAgent);
  const allowedAgent = user.userAgent.includes(thisUserAgent);

  //Trigger 2FA
  if (!allowedAgent) {
    //Generate 6 digits code
    const loginCode = Math.floor(100000 + Math.random() * 900000);
    console.log(loginCode);
    //Encrypt login code before saving to DB
    const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

    //Delete token if exists in DB
    let userToken = await Token.findOne({ userId: user._id });
    if (userToken) {
      await userToken.deleteOne();
    }

    //Save token and save
    await new Token({
      userId: user._id,
      lToken: encryptedLoginCode,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * (60 * 1000), //60 mins
    }).save();

    res.status(400);
    throw new Error("New device has been detected");
  }

  //Generate the Token
  const token = generateToken(user._id);
  if (user && passwordIsCorrect) {
    //Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), //1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, username, email, phone, bio, photo, role, isVerified } = user;
    res.status(200).json({
      _id,
      username,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  } else {
    res.status(500);
    throw new Error("Something went wrong, please try again");
  }
});

const sendLoginCode = asyncHandler(async (req, res) => {
  const { user_name } = req.params;
  const user = await User.findOne({ username: user_name });
  console.log(user);
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  //Find Login code in DB

  let userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token, please login code");
  }

  const loginCode = userToken.lToken;
  const decryptedLoginCode = cryptr.decrypt(loginCode);

  //Send Login Code
  const subject = "Login Access Code - Melodify";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@melodify.com";
  const template = "loginCode";
  const username = user.username;
  const link = decryptedLoginCode;

  try {
    sendEmail(subject, send_to, sent_from, reply_to, template, username, link);
    res.status(200).json({ message: `Access code sent to ${user.email}` });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again!", error);
  }
});

const loginWithCode = asyncHandler(async (req, res) => {
  const { user_name } = req.params;
  const { code } = req.body;

  const user = await User.findOne({ username: user_name });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // Find user login token
  let userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token, please login code");
  }

  const decryptedLoginCode = cryptr.decrypt(userToken.lToken);

  if (decryptedLoginCode !== code) {
    res.status(400);
    throw new Error("Login code doesn't match, please try again");
  } else {
    //Register user agent
    const ua = parser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;

    user.userAgent.push(thisUserAgent);
    await user.save();

    //Log the user in

    //Generate the Token
    const token = generateToken(user._id);

    //Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), //1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, username, email, phone, bio, photo, role, isVerified } = user;
    res.status(200).json({
      _id,
      username,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
});

const sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("User not found!");
  }

  if (user.isVerified) {
    res.status(400);
    throw new Error("User already verified!");
  }

  //Delete token if exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  //Create Verification Token
  const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(verificationToken);
  //Hash token and save
  const hashedToken = hashToken(verificationToken);
  await new Token({
    userId: user._id,
    vToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000), //60 mins
  }).save();

  // Construct Verification URL

  const verificationURL = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

  //Send Verification Email
  const subject = "Verify Your Account - Melodify";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@melodify.com";
  const template = "verifyEmail";
  const username = user.username;
  const link = verificationURL;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      username,
      link
    );
    res.status(200).json({ message: "Verification Email sent!" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again!", error);
  }
});

//Verify User
const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  const hashedToken = hashToken(verificationToken);

  const userToken = await Token.findOne({
    vToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token");
  }

  // Find user
  const user = await User.findById(userToken.userId);

  if (user.isVerified) {
    res.status(400);
    throw new Error(
      "Your Email is already verified. You can continue using the application"
    );
  }

  // Now verify user
  user.isVerified = true;
  await user.save();

  res.status(200).json({
    message: "Your Email was verified. You can continue using the application",
  });
});

const logoutUser = asyncHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0), //now
    sameSite: "none",
    secure: true,
  });

  return res.status(200).json({ message: "Logout successful!" });
});
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, username, email, phone, bio, photo, role, isVerified } = user;
    res.status(200).json({
      _id,
      username,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
    });
  } else {
    res.status(404);
    throw new Error("User not found!");
  }
});

const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { username, email, phone, bio, photo, role, isVerified } = user;
    user.username = req.body.username || username;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;
    user.email = email;

    const updatedUser = await user.save();

    res.status(200).json({
      _id: updatedUser._id,
      username: updatedUser.username,
      email: updatedUser.email,
      phone: updatedUser.phone,
      bio: updatedUser.bio,
      photo: updatedUser.photo,
      role: updatedUser.role,
      isVerified: updatedUser.isVerified,
    });
  } else {
    res.status(404);
    throw new Error("User not found!");
  }
});

const deleteUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  await user.deleteOne();
  res.status(200).json({ message: "User deleted successfully" });
});

const getAllUsers = asyncHandler(async (req, res) => {
  const users = await User.find().sort("-createdAt").select("-password");

  if (!users) {
    res.status(404);
    throw new Error("Something went wrong");
  }

  res.status(200).json(users);
});

const getLoginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.json(false);
  }

  // Verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET);

  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});

const updateUserRole = asyncHandler(async (req, res) => {
  const { role, id } = req.body;

  const user = await User.findById(id);

  if (!user) {
    res.status(404);
    throw new Error("User not found!");
  }

  user.role = role;
  await user.save();

  res.status(200).json({ message: `User role has been changed to ${role}` });
});

const sendAutomatedEmail = asyncHandler(async (req, res) => {
  const { subject, send_to, reply_to, template, url } = req.body;

  if (!subject || !send_to || !reply_to || !template) {
    res.status(404);
    throw new Error("Missing Email Parameter");
  }

  const user = await User.findOne({ email: send_to });

  if (!user) {
    res.status(404);
    throw new Error("User not found!");
  }

  const sent_from = process.env.EMAIL_USER;
  const username = user.username;
  const link = `${process.env.FRONTEND_URL}${url}`;
  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      username,
      link
    );
    res.status(200).json({ message: "Email sent successfully" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again!", error);
  }
});

const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("No user found with this email!");
  }

  //Delete token if exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  //Create Verification Token
  const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  //Hash token and save
  const hashedToken = hashToken(resetToken);
  await new Token({
    userId: user._id,
    rToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000), //60 mins
  }).save();

  // Construct Reset URL

  const resetURL = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

  //Send Reset Email
  const subject = "Password Reset Request - Melodify";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@melodify.com";
  const template = "forgotPassword";
  const username = user.username;
  const link = resetURL;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      username,
      link
    );
    res.status(200).json({ message: "Password Reset Email sent!" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again!", error);
  }
});

//Reset Password
const resetPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;

  const hashedToken = hashToken(resetToken);
  console.log(hashedToken);
  const userToken = await Token.findOne({
    rToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token");
  }

  // Find user
  const user = await User.findById(userToken.userId);

  // Now Reset Password
  user.password = password;
  await user.save();

  res
    .status(200)
    .json({ message: "Password successfully changed! Please Login" });
});

const changePassword = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  const { oldPassword, password } = req.body;

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  if (!oldPassword || !password) {
    res.status(400);
    throw new Error("Please old and new password");
  }

  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

  if (user && passwordIsCorrect) {
    // Now Change Password
    user.password = password;
    await user.save();
  } else {
    res.status(400);
    throw new Error("Password doesn't match");
  }

  //Delete token if exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  //Create Verification Token
  const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  //Hash token and save
  const hashedToken = hashToken(resetToken);
  await new Token({
    userId: user._id,
    rToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000), //60 mins
  }).save();

  const resetURL = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

  //Send Reset Email
  const subject = "Password Change - Melodify";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@melodify.com";
  const template = "changePassword";
  const username = user.username;
  const link = resetURL;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      username,
      link
    );
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again!", error);
  }
  res.status(200).json({
    message: "Password successfully changed! Please re-login",
    emailMessage: "Password Change Email sent!",
  });
});
const loginWithGoogle = asyncHandler(async (req, res) => {
  const { userToken } = req.body;

  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();

  const { name, email, picture, sub } = payload;
  const password = Date.now() + sub;

  const [firstName, lastName] = name.split(" ");
  let baseUsername = firstName.toLowerCase();

  if (lastName) {
    baseUsername += `.${lastName.toLowerCase()}`;
  }

  // Generate a unique username
  let username = baseUsername;
  let isUnique = false;
  let attempt = 0;

  while (!isUnique) {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      attempt++;
      username = `${baseUsername}${attempt}`;
    } else {
      isUnique = true;
    }
  }

  //Get UserAgent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  // Check if user exists
  const user = await User.findOne({ email });

  if (!user) {
    //Create new User
    const newUser = await User.create({
      username,
      email,
      password,
      photo: picture,
      isVerified: true,
      userAgent,
    });

    if (newUser) {
      //Generate the Token
      const token = generateToken(newUser._id);

      //Send HTTP-only cookie
      res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), //1 day
        sameSite: "none",
        secure: true,
      });

      const { _id, username, email, phone, bio, photo, role, isVerified } =
        newUser;
      res.status(201).json({
        _id,
        username,
        email,
        phone,
        bio,
        photo,
        role,
        isVerified,
        token,
      });
    }
  }
  //User exists, Login
  if (user) {
    const token = generateToken(user._id);

    //Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), //1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, username, email, phone, bio, photo, role, isVerified } = user;
    res.status(201).json({
      _id,
      username,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
});
export {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
  getAllUsers,
  getLoginStatus,
  updateUserRole,
  sendAutomatedEmail,
  sendVerificationEmail,
  verifyUser,
  forgotPassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle,
};
