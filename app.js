// app.js (or index.js)

const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const flash = require('connect-flash');
const bcrypt = require('bcrypt');

const app = express();

// Set up middleware
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'your-secret-key',
    resave: true,
    saveUninitialized: true
}));
app.use(flash());

// In-memory user store (replace this with a proper database in a production environment)
const users = [];

// Passport.js local strategy
const LocalStrategy = require('passport-local').Strategy;
const passport = require('passport');

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, (email, password, done) => {
    const user = users.find(u => u.email === email);
    if (!user) {
        return done(null, false, { message: 'Incorrect email.' });
    }
    if (!bcrypt.compareSync(password, user.password)) {
        return done(null, false, { message: 'Incorrect password.' });
    }
    return done(null, user);
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    const user = users.find(u => u.id === id);
    done(null, user);
});

// Routes
app.post('/auth/signup', (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = { id: Date.now().toString(), email, password: hashedPassword };
    users.push(newUser);
    req.flash('success', 'Account created successfully. Please log in.');
    res.redirect('/auth/login'); // Redirect to the login route
});

app.post('/auth/login', passport.authenticate('local', {
    successRedirect: '/home',
    failureRedirect: '/auth/login',
    failureFlash: true,
}));

app.get('/auth/logout', (req, res) => {
    req.logout();
    req.flash('success', 'You are now logged out.');
    res.redirect('/');
});

app.post('/auth/reset-password', (req, res) => {
    // Your reset password logic here
    res.redirect('/home');
});

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/views/home.html');
});

// Add this route for signup, since it's using GET method
app.get('/auth/signup', (req, res) => {
    res.sendFile(__dirname + '/views/signup.html');
});

// Add this route for login, since it's using GET method
app.get('/auth/login', (req, res) => {
    res.sendFile(__dirname + '/views/login.html');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
