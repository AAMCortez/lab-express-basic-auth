const router = require("express").Router();
const bcrypt = require("bcryptjs");
const saltRounds = 10;
const User = require("../models/User.model");
const mongoose = require("mongoose");

/* GET home page */
router.get("/", (req, res, next) => {
   res.render("index");
});

router.get("/signup", (req, res, next) => {
   try {
      res.render("signup");
   } catch (error) {
      next(error);
   }
});

router.post("/signup", async (req, res, next) => {
   try {
      const { username, password } = req.body;
      if (!username || !password) {
         return res.render("signup", {
            errorMessage: "All fields are required",
         });
      }
      const salt = await bcrypt.genSalt(saltRounds);
      const passwordHash = await bcrypt.hash(password, salt);
      await User.create({ username, passwordHash });
      res.redirect("/profile");
   } catch (error) {
      next(error);
   }
});
router.get("/profile", (req, res, next) => {
   try {
      const { currentUser } = req.session;
      res.render("profile", currentUser);
   } catch (error) {
      next(error);
   }
});

router.get("/login", (req, res, next) => {
   try {
      res.render("login");
   } catch (error) {
      next(error);
   }
});

router.post("/login", async (req, res, next) => {
   try {
      const { username, password } = req.body;

      if (username === "" || password === "") {
         return res.render("login", {
            errorMessage: "Please enter both username and password",
         });
      }
      const user = await User.findOne({ username });
      if (!user) {
         return res.render("login", {
            errorMessage:
               "Username is not registered. Please try another username.",
         });
      } else if (bcrypt.compareSync(password, user.passwordHash)) {
         req.session.currentUser = user;
         res.redirect("/profile");
      } else {
         res.render("login", { errorMessage: "Incorrect password" });
      }
   } catch (error) {
      next(error);
   }
});

module.exports = router;
