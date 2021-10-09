//jshint esversion:6
require('dotenv').config();
const express = require('express');
const BodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require('passport-facebook');

const app = express();

app.use(BodyParser.urlencoded({extended:true}));
app.use(express.static('public'));
app.set('view engine','ejs');
app.use(session(
    {
        secret:process.env.SECRET,
        resave:true,
        saveUninitialized:false
    }));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/SecretsDB');
const userdataSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    facebookId:String
});

// userdataSchema.plugin(encrypt,{secret:process.env.SECRETS , encryptedFields:["password"]});
userdataSchema.plugin(passportLocalMongoose)
userdataSchema.plugin(findOrCreate)
const Data = mongoose.model('data',userdataSchema);

passport.use(Data.createStrategy());
passport.serializeUser(function(user, done) 
{
    done(null, user.id);
});
  
passport.deserializeUser(function(id, done) 
{
    Data.findById(id, function(err, user) 
    {
        done(err, user);
    });
});

passport.use(new GoogleStrategy(
    {
        clientID:process.env.CLIENT_ID,
        clientSecret:process.env.CLIENT_SECRET,
        callbackURL:"http://localhost:3000/auth/google/secrets"
    },
    function(accessToken , refreshToken , profile , cb)
    {
        Data.findOrCreate({googleId:profile.id},function(err,user)
        {
            return cb(err,user);
        })
    }
));

passport.use(new FacebookStrategy(
    {
        clientID:process.env.FACEBOOK_APP_ID,
        clientSecret:process.env.FACEBOOK_APP_SECRET,
        callbackURL:"http://localhost:3000/auth/facebook/secrets"
    },
    function(accessToken,refreshToken,profile,cb)
    {
        Data.findOrCreate({facebookId:profile.id},function(err,user)
        {
            return cb(err,user);
        })
    }
))

app.get('/auth/google', passport.authenticate('google',{scope:["profile"]}));

app.get('/auth/google/secrets',passport.authenticate('google',{failureRedirect:'/login'}),function(req,res)
{
    res.redirect('/secrets');
})

app.get('/auth/facebook',passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',passport.authenticate('facebook',{failureRedirect:'/login'}),function(req,res)
{
    res.redirect('/secrets');
})

app.get('/',function(req,res)
{
    res.render('home');
});

app.get('/login',function(req,res)
{
    res.render('login');
}); 

app.get('/secrets',function(req,res)
{
    if(req.isAuthenticated())
    {
        res.render('secrets');
    }
    else
    {
        res.redirect('/login');
    }
})

app.get('/register',function(req,res)
{
    res.render('register');
});

app.post('/register',function(req,res)
{
    Data.register({username:req.body.username},req.body.password,function(err,user)
    {
        if(err)
        {
            console.log(err);
            res.redirect('/register');
        }
        else
        {
            passport.authenticate('local')(req,res,function()
            {
                res.redirect('/secrets');
            })
        }
    })
});

app.post('/login',function(req,res)
{
    const user = new Data({
        email:req.body.username,
        password:req.body.password
    })

    req.login(user,function(err)
    {
        passport.authenticate('local')(req,res,function()
        {
            res.redirect('/secrets');
        })
    })
});

app.get('/logout', function(req, res)
{
    req.logout();
    res.redirect('/');
});

app.listen(3000,function()
{
    console.log('Server is up and started on port 3000!');
});