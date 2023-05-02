require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 8080;

const app = express();
const path = require('path');
const Joi = require("joi");

const expireTime = 1;



// Declaring variables to store sensitive information, such as database credentials and session secrets:

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */


// Importing the database connection file and creating a 
// reference to the users collection
const { database } = require('./databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');


// Configuring express to use url-encoded data in request bodies
app.use(express.urlencoded({ extended: false }));


// Creating a MongoStore instance to handle session storage using the MongoDB driver
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret
  }
})


// Configuring session middleware with a secret and the MongoStore instance, 
// and setting saveUninitialized and resave to false and true respectively.
app.use(session({
  secret: node_session_secret,
  store: mongoStore, //default is memory store 
  saveUninitialized: false,
  resave: true,
  cookie: {
    maxAge: 60 * 60 * 1000 // 1 hour in milliseconds
  }
}));


// A home page links to signup and login, if not logged in; and links to members and signout, if logged in.
app.get('/', (req, res) => {
  res.send(`
        <h1>Welcome to my App!</h1>
        <body>
        <p>
        My name is Gathrean Dela Cruz <br>
        From Set 2A <br>
        This is a demo for Assignment 1 <br>
        </p>
        <h2> Let's begin! </h2>
        </body>
        <a href="/signup"><button>Sign Up</button></a>
        <a href="/login"><button>Login</button></a>
    `);
});

app.get('/nosql-injection', async (req, res) => {

  // Get the 'user' query parameter from the request
  var username = req.query.user;

  // If no user parameter was provided, display a message with instructions on how to use the endpoint
  if (!username) {
    res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
    return;
  }

  // Log the username to the console
  console.log("user: " + username);

  // Validate the username using the Joi library to prevent NoSQL injection attacks
  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  /*
   If we didn't use Joi to validate and check for a valid URL parameter below
   we could run our userCollection.find and it would be possible to attack.
   A URL parameter of user[$ne]=name would get executed as a MongoDB command
   and may result in revealing information about all users or a successful
   login without knowing the correct password.
   */

  // if the validation failed, log an error and sends a message to the client 
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
    return;
  }

  // If the validation passed, perform a MongoDB find operation on the userCollection using the username as the search criteria
  const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

  // Log the result of the MongoDB find operation to the console
  console.log(result);

  // Display a message to the client that says "Hello"
  res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req, res) => {
  var color = req.query.color;

  res.send("<h1 style='color:" + color + ";'>Gathrean Dela Cruz</h1>");
});



app.get('/signup', (req, res) => {
  var html = `
    <h1>Create User</h1>
    <form action='/submitUser' method='post'>
      <input id='username' name='username' type='text' placeholder='Username' required>
      <br>
      <input id='email' name='email' type='email' placeholder='Email' required>
      <br>
      <input id='password' name='password' type='password' placeholder='Password' required>
      <br><br>
      <button type='submit'>Submit</button>
    </form>
  `;
  res.send(html);
});



app.get('/login', (req, res) => {
  var html = `
    <h1>Login</h1>
    <form action='/loggingin' method='post'>
      <input id='email' name='email' type='email' placeholder='Email' required>
      <br>
      <input id='password' name='password' type='password' placeholder='Password' required>
      <br><br>
      <button>Submit</button>
    </form>
    `;
  res.send(html);
});


// Called when the user clicks the submit button on the login form.
app.post('/submitUser', async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object(
    {
      username: Joi.string().required(),
      email: Joi.string().required(),
      password: Joi.string().required()
    });

  const validationResult = schema.validate({ username, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/signup");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  try {
    const existingUser = await userCollection.findOne({ email: email });
    if (existingUser) {
      console.log("Email already registered!");
      res.redirect("/signup");
    } else {
      const newUser = {
        username: username,
        email: email,
        password: hashedPassword,
      };

      const insertResult = await userCollection.insertOne(newUser);
      console.log(insertResult);
      res.redirect("/members"); // add this line
    }
  } catch (error) {
    console.log(error);
    res.redirect("/signup");
  }
});



// Called when the user clicks the submit button on the login form.
app.post('/loggingin', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const user = await userCollection.findOne({ email });

  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.username = user.username;
    req.session.email = email;
    req.session.loggedIn = true;

    req.session.cookie.expires = new Date(Date.now() + expireTime * 60 * 60 * 1000); // expire after 1 hour

    res.redirect('/members');
  } else {
    console.log("Invalid email/password combination.");
    res.send(`
      <b>Invalid email/password combination.</b> <br>
      <a href="/login"><button>Try again</button></a>
    `);
  }
});



// If user is not logged in, redirect to login page.
app.get('/loggedin', (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
  }
  var html = `
    You are logged in!
    `;
  res.send(html);
});


// Array for random images found in public folder
const images = ["image1.jpeg", "image2.jpeg", "image3.jpeg"];
const getRandomImage = () => images[Math.floor(Math.random() * images.length)];


// Members page that only logged in users can access
app.get('/members', (req, res) => {
  const username = req.session.username;
  const image = getRandomImage();
  if (!username) {
    res.redirect('/login');
  } else {
    res.send(`
    <h1>Welcome back, ${username}!</h1>
    
    <form action="/logout" method="POST">
      <button type="submit">Logout</button>
    </form>

    <p> Here's a random photo of an orca to improve your day!</p>
    <img src="${image}" alt="Random Orca image for your day!">
  `);
  }
});

// Serve static files from the 'public' folder
app.use(express.static('public'));

// Redirects to home page when user logs out and destroys session
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    } else {
      res.redirect('/');
    }
  });
});


// Logs out user and destroys session
// Sends a message to the user that they are logged out
app.get('/logout', (req, res) => {
  req.session.destroy();
  var html = `
    You are logged out.
    `;
  res.send(html);
});


// Serve static files from the 'public' folder
app.use(express.static(__dirname + "/public"));


// 404 error page
app.get("*", (req, res) => {
  res.status(404);
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8">
        <title>404. That’s an error.</title>
      </head>
      <body>
        <div class="wrapper">
          <div class="error-code"><h1>404. That’s an error :(<h1></div>
          <br>
          <div class="error-description">The requested URL ${req.url} was not found on this server. <br><br> That’s all we know.</div>
        </div>
      </body>
    </html>
  `;
  res.send(html);
})

// States which port to listen on
app.listen(port, () => {
  console.log("Node application listening on port " + port);
});

