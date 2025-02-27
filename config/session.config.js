const session = require("express-session");
const MongoStore = require("connect-mongo");
const mongoose = require("mongoose");

module.exports = (app) => {

   app.set("trust proxy", 1);
   app.use(
      session({
         secret: process.env.SESSION_SECRET,
         resave: true,
         saveUninitialized: false,
         cookie: {
            samesite: process.env.NODE_ENV === "production" ? "none" : "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: 60000,
         },
         rolling: true,
         store: MongoStore.create({
            mongoUrl:
               process.env.MONGODB_URI || "mongodb://localhost/lab-express-basic-auth",
         }),
      })
   );
};
