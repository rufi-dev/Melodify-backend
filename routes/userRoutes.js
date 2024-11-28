import express from "express";
const router = express.Router();
import { protect, adminOnly } from "../middleware/authMiddleware.js";
import {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  sendAutomatedEmail,
  sendVerificationEmail,
  deleteUser,
  getAllUsers,
  getLoginStatus,
  updateUserRole,
  verifyUser,
  forgotPassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle
} from "../controllers/userController.js";

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/logout", logoutUser);
router.get("/getUser", protect, getUser);
router.patch("/updateUser", protect, updateUser);
router.delete("/deleteUser/:id", protect, adminOnly, deleteUser);
router.get("/getAllUsers", protect, adminOnly, getAllUsers);
router.get("/getLoginStatus", getLoginStatus);
router.patch("/updateUserRole", protect, adminOnly, updateUserRole);
router.post("/sendAutomatedEmail", protect, sendAutomatedEmail);
router.post("/sendVerificationEmail", protect, sendVerificationEmail);
router.patch("/verifyUser/:verificationToken", verifyUser);
router.post("/forgotPassword", forgotPassword);
router.patch("/resetPassword/:resetToken", resetPassword);
router.patch("/changePassword", protect, changePassword);
router.post("/sendLoginCode/:user_name", sendLoginCode);
router.post("/loginWithCode/:user_name", loginWithCode);
router.post("/google/callback", loginWithGoogle);

export default router;
