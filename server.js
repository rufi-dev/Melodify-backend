import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import bodyParser from "body-parser";
import cors from "cors";
import cookieParser from "cookie-parser";
import userRoute from "./routes/userRoutes.js";
import errorHandler from "./middleware/errorMiddleware.js";

dotenv.config();
const app = express();

//Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(
  cors({
    origin: ["http://localhost:5173", "https://musicmelodify.vercel.app"],
    credentials: true,
  })
);

//Routes
app.use("/api/users", userRoute);

app.get("/", (req, res) => {
  res.send("Home Page");
});

//Error Handler
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on ${PORT}`);
    });
  })
  .catch((err) => console.log(err));
