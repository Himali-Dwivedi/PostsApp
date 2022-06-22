//jshint esversion:6

/*
    It is not a good practice to keep the API keys, encryption keys and other critical data hard-coded in the program. 
    Therefore, we are using this module that creates environment variables to store such data.
    Always remember to import this module right at the top of your program.
*/
require("dotenv").config(); 

const express = require("express");
const body_parser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passport_local_mongoose = require("passport-local-mongoose");
var GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const findOrCreate = require("mongoose-findorcreate");

/*
    This module is used for encrypting passwords in our app. This uses modern encryption method i.e., AES.
    This method takes the encyption key to encrypt and the decrypt the data whenever needed.
    This is a good approach to keep the data secure. However, It is not that effective.
    It is not going to be much difficult for any motivated hacker to decipher the data, if we use this approach. This is just for level-1 security.
*/
// const encrypt = require("mongoose-encryption");    

/*
    For Level-2 security,we are going to replace our previous mongoose-encryption method to Hash-encryption method.
    Hash encryption is only one way, which means it can be encrypted in like a few milliseconds but it would take years to decrypt the data.
    Hash encryption method is the most secure approach as it does not require any encrption key, which makes this approach almost unhijackable.
    In this approach, our data is first translated into a hash value by the hash function (which itself is a mathematical equation) which is then stored into the database. 
    And whenever a user again logs into the system, the entered data is again converted into a hash value which is then compared to the data which is stored in the DB.
    Hash function generates same hash value for the same input string. Because of this, we are able to compare the login credentials against the crendentials stored in the DB.
    However, this is also a drawback of this approach. On google, people has already published a hash table for the bunch of most commonly used passwords.
    This makes it easier for anyone either a noob or a hacker to hijack the account by just comparing the hashed password against the hash table on the internet.
    To keep the account secure, try not to use the commonly used password. Keep the length of the password memorably long.  
*/
// const md5 = require("md5");

/*
    Here comes another module to encryption.
    Introducing the concept of salting and salt rounds
    To install this module, use the below syntax (if you are using the node version >= 12):
        npm install bcrypt@latest
*/    
// const bcrypt = require("bcrypt");
// const salt_round = 2;

const app = express();
app.use(body_parser.urlencoded({extended: true}));
app.set("view engine", "ejs");
app.use(express.static("public"));

/*
    Setting up the session
    The below line must be written before the mongoose.connect() statement
*/
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

/*
    Setting up the passport
    passport allows us to enable authentication from google, facebook, linkedIn, Instagram, Twitter etc.
    After initializing the passport, we are embedding a session with it.
    Note: The order of statements and code blocks are very important here. Try to keep the order same as it is here
*/
app.use(passport.initialize());
app.use(passport.session());

/*
  Getting current user
*/
// var current_user;
// app.use(function(req,res,next){
//     current_user = req.user;
//     console.log("Current User: " + current_user);
//     next();
// });


mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

const user_schema = new mongoose.Schema({
    email:{
        type: String,
    },
    password:{
        type: String,
    },
    googleId: {
        type: String,
    },
    secret: [String]
});
/*
    passport_local_mongoose plugin is going to all the heavy lifting behinf the scene for us.
    It will hash and salt the password and then store it into the mongo DB.
*/
user_schema.plugin(passport_local_mongoose);
/*
 The below statement is required for Google Auth 2.0
*/
user_schema.plugin(findOrCreate);

/*
    It is important to encrypt the schema by using the below statement before using it in the model.
    Mongoose-encryption encrypts the whole database unless you specify a value for "encryptedFields" key
    Moongoose-encryption automatically encrypts the data when we call save() and decrypys it when we call find().
    Below we created a variable "secret" that holds a long string. This string plays a significant role as a key in encrypting the data. 
*/

/*
    Moved the below encryption key to the .env file.
    .env stands for environment variables. This is not a file extension. This file holds all the confidential data in the form of KEY:value. 
    These pairs have no spaces, key is always capitalized and values are just plain text so we can type basically anything with or without punctations.
    In order for environment variables to work, the name of the file must be same as .env. You can't name the file anything else.
    To call the environment variables in the main code, use the below syntax:
        process.env.<key_name>
*/

/*
    The below line of codes are no longer required as they are replaced by the statements for hash encyption (md5) 
*/
// const secret = process.env.SECRET;
// user_schema.plugin(encrypt, {secret: secret, encryptedFields: ["password"]});


const User = new mongoose.model("User",user_schema);

/*
    passport also takes care of the serialization and deserialization of cookies
*/
passport.use(User.createStrategy());
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {
    done(null, user);
  });
  
  passport.deserializeUser(function(user, done) {
    done(null, user);
  });


/*
  Setting up Google Auth
*/
passport.use(new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback   : true
  },
  function(request, accessToken, refreshToken, profile, done) {
    // console.log("profile: " + profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));


app.listen(3000, function(){
    console.log("Server is up and running on Port 3000");
});

app.get("/", function(request, response){
    response.render("home");
});

/*
    Displaying google signin page on /auth/google
*/
app.get("/auth/google",
  passport.authenticate('google', { scope:
      [ "email", "profile" ] }
));


app.get( "/auth/google/secrets",
    passport.authenticate( "google", {
        successRedirect: "/secrets",
        failureRedirect: "/login"
}));

app.get("/login", function(request, response){
    response.render("login");
});

app.get("/register", function(request, response){
    response.render("register");
});

app.get("/secrets", function(request, response){
    // if(request.isAuthenticated()){
    //     response.render("secrets");
    // }else{
    //     response.redirect("/login");
    // }

    var is_logged_in;
    if(request.isAuthenticated()){
        is_logged_in = true;
    }else{
        is_logged_in = false;
    }

    User.find({secrets: {$ne: null}}, function(error, found_results){
        if(error){
            console.log(error);
        }else{
            response.render("secrets", {user_with_secrets: found_results, login_status: is_logged_in});
        }
    });
});

app.get("/submit", function(request, response){
    if(request.isAuthenticated()){
        response.render("submit");
    }else{
        response.redirect("/login");
    }
});

app.post("/submit", function(request, response){
    const submitted_secret = request.body.secret;

    //passport saves the user details when the user logs in. We can access those details with request.user property
    // console.log("userID: " + request.user._id);
    User.findById(request.user._id, function(error, found_user){
        if(error){
            console.log(error);
        }else{
            found_user.secret.push(submitted_secret);
            found_user.save(function(error){
                if(error){
                    console.log(error);
                }else{
                    response.redirect("/secrets");
                }
            });
        }
    });
});

app.get("/logout", function(request, response){
    request.logOut(function(error){
        if(error){
            console.log(error);
        }else{
            response.redirect("/");
        }
    });
});

app.post("/register", function(request, response){
    //the below register() is comming from passport-local-mongoose module.
    User.register({username: request.body.username}, request.body.password, function(error, user){
        if(error){
            console.log(error);
            response.redirect("/register");
        }else{
            passport.authenticate("local")(request, response, function(){
                response.redirect("/secrets");
            });
        }
    });
});

app.post("/login", function(request, response){
    const user = new User({
        email: request.body.username,
        password: request.body.password
    });

    request.login(user, function(error){
        if(error){
            console.log(error);
        }else{
            passport.authenticate("local")(request, response, function(){
                response.redirect("/secrets");
            });
        }
    });
});