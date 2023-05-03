const express = require("express");
const http = require("http");
const socketIO = require("socket.io");
const mongoose = require("mongoose");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
const {
  RateLimiterRedis,
  RateLimiterMemory,
} = require("rate-limiter-flexible");
const Redis = require("ioredis");

const app = express();
const server = http.createServer(app);
const io = socketIO(server);
const redisClient = new Redis();

// MongoDB connection
mongoose.connect("mongodb://localhost/chat", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});

// User schema and model
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
});

UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const User = mongoose.model("User", UserSchema);

// Passport authentication
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username });
      if (!user) return done(null, false);
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) return done(null, false);
      return done(null, user);
    } catch (error) {
      done(error);
    }
  })
);

// Rate limiting
const rateLimiter = new RateLimiterRedis({
  storeClient: redisClient,
  keyPrefix: "rlflx",
  points: 10,
  duration: 1,
});

// Chat-related logic
io.use((socket, next) => {
  rateLimiter
    .consume(socket.handshake.address)
    .then(() => next())
    .catch(() => {
      const err = new Error("Too Many Requests");
      err.status = 429;
      next(err);
    });
});

io.on("connection", (socket) => {
  // Implement chat logic here
});

server.listen(3000, () => {
  console.log("Server is running on port 3000");
});
