//jshint esversion:6
require('dotenv').config();
const express = require('express');
const BodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();

app.use(BodyParser.urlencoded({extended:true}));
app.use(express.static('public'));
app.set('view engine','ejs');

mongoose.connect('mongodb://localhost:27017/SecretsDB');
const userdataSchema = new mongoose.Schema({
    email:String,
    password:String
});

// userdataSchema.plugin(encrypt,{secret:process.env.SECRETS , encryptedFields:["password"]});

const Data = mongoose.model('data',userdataSchema);

app.get('/',function(req,res)
{
    res.render('home');
});

app.get('/login',function(req,res)
{
    res.render('login');
}); 

app.get('/register',function(req,res)
{
    res.render('register');
});

app.post('/register',function(req,res)
{
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) 
    {
        const data = new Data({
            email:req.body.username,
            password:hash
        })
        data.save(function(err)
        {
            if(err)
            {
                console.log(err);
            }
            else
            {
                res.render('secrets');
            }
        })
    });
});

app.post('/login',function(req,res)
{
    const userEmail = req.body.username;
    const userPassword = req.body.password;
    
    Data.findOne({email:userEmail},function(err,foundUser)
    {
        if(!err)
        {
            if(foundUser)
            {
                bcrypt.compare(userPassword, foundUser.password, function(err, result) 
                {
                    console.log(result);
                   if(result === true)
                   {
                        res.render('secrets');
                   }
                });
            }
        }
    })
});

app.listen(3000,function()
{
    console.log('Server is up and started on port 3000!');
});