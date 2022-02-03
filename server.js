const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require("cookie-parser");
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const User = require('./model/User');
dotenv.config();


//Connect to DB
mongoose
    .connect(process.env.DB_CONNECT, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log("Database connected!"))
    .catch(err => console.log(err));



const app = express();

app.use(cors());
app.use(express.json());
app.use(cookieParser()); //will parse the Cookie header and handle cookie separation and encoding

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (username && password) {
        //Checking if the user is already in the database
        const usernameExist = await User.findOne({ username: username });
        if (usernameExist) return res.status(400).json({ error: 'User already exists' });


        //hash password
        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password, salt);

        //CREATE A NEW USER
        const user = new User({
            username: username,
            password: hashPassword
        });

        try {
            const savedUser = await user.save();
            res.send({ user: savedUser });
            res.status(200).json({ message: 'User registerd' });
        } catch (e) {
            res.status(400).json({ error: e });
        }
    }

})

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    //checking if the user exist
    const user = await User.findOne({ username: username });
    if (!user) return res.status(400).json({ error: "Invalid user" });

    //checking if the password is correct
    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).json({ error: "Invalid password" });

    //If the user exists, create and assign a token
    if (user) {
        const token = jwt.sign({ _id: user._id }, process.env.TOKEN_SECRET, {
            expiresIn: 300,
        });
        res.cookie("access-token", token, {
            maxAge: 60 * 60 * 24 * 30 * 1000, //expires in 30 days
            httpOnly: true, //do not let the user access the token in the brownser, way more secure
        });

        res.json('User logged in!')
    } else {
        return res.status(400).json({ error: "An error ocurred when trying to login" });
    }


})

//middleware to check the jwt token created
const validateToken = (req, res, next) => {
    const accessToken = req.cookies["access-token"];

    if (!accessToken) return res.status(400).json({ error: "User not Authenticated!" });


    jwt.verify(accessToken, process.env.TOKEN_SECRET, (err) => {
        if (err) return res.status(400).json({ error: err });;

        req.authenticated = true;
        next();
    });
}

app.get('/profile', validateToken, (req, res) => {
    res.json('Profile');
})


app.listen(3001, () => {
    console.log(`Server running on port: 3001`);
});





