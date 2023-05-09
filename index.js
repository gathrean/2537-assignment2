require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const Joi = require("joi");
const app = express();
const expireTime = 3600000; // 1 hour

const port = process.env.PORT || 8080;

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

userCollection.createIndex({ username: 1 }, { unique: true });
userCollection.createIndex({ email: 1 }, { unique: true });
userCollection.createIndex({ user_type: 1 });



// Configuring express to use url-encoded data in request bodies
app.use(express.urlencoded({ extended: false }));

app.set('view engine', 'ejs');

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


// HOME
app.get('/', (req, res) => {
  res.render("index");
});

// Middleware function to check if the user is authenticated and has admin access
const isAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.user_type === "admin") {
    // If the user is an admin, allow them to access the /admin page
    next();
  } else {
    // If the user is not an admin, redirect them to the /login page
    res.redirect('/login');
  }
};






function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req) && isAdmin(req)) {
    next();
  } else {
    res.redirect('/login');
  }
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("errorMessage", { error: "Not Authorized" });
    return;
  }
  else {
    next();
  }
}



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
  const validationResult = schema.validate(req.body);

  /*
   If we didn't use Joi to validate and check for a valid URL parameter below
   we could run our userCollection.find and it would be possible to attack.
   A URL parameter of user[$ne]=name would get executed as a MongoDB command
   and may result in revealing information about all users or a successful
   login without knowing the correct password.
   */

  // if the validation failed, log an error and sends a message to the client 
  if (validationResult.error) {
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

// Route for the admin dashboard
app.get('/admin', sessionValidation, adminAuthorization, (req, res) => {
  res.render("admin");
});


//PROMO AND DEMOTE
const ObjectId = require('mongodb').ObjectId;

//PROMOTE AND DEMOTE
app.post('/promoteUser', adminAuthorization, async (req, res) => {

  try {
    const userId = req.body.user_id;
    const updatedUser = await userCollection.findOneAndUpdate(
      { _id: ObjectId(userId) },
      { $set: { user_type: 'admin' } }
    );
    if (!updatedUser) {
      res.render("errorMessage", { error: "User not found" });
      return;
    }
    res.redirect('/admin');
  } catch (error) {
    console.log(error);
    res.render("errorMessage", { error: "Something went wrong" });
  }
});

app.post('/demoteUser', adminAuthorization, async (req, res) => {

  try {
    const userId = req.body.user_id;
    const updatedUser = await userCollection.findOneAndUpdate(
      { _id: ObjectId(userId) },
      { $set: { user_type: 'user' } }
    );
    if (!updatedUser) {
      res.render("errorMessage", { error: "User not found" });
      return;
    }
    res.redirect('/admin');
  } catch (error) {
    console.log(error);
    res.render("errorMessage", { error: "Something went wrong" });
  }
});



// SIGN UP
app.get('/signup', (req, res) => {
  res.render("signup");
});



// Called when the user clicks the submit button on the login form.
app.post('/submitUser', async (req, res) => {
  const { username, email, password } = req.body;

  // Define a new user object with default user_type value
  const newUser = {
    username,
    email,
    password,
    user_type: 'user' // Set default user_type value
  };

  // Use Joi to validate the new user object
  const schema = Joi.object({
    username: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required(),
    user_type: Joi.string().valid('admin', 'user').required()
  });

  try {
    await schema.validateAsync(newUser);

    // Hash the password before storing it in the database
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Save the user to the database
    const result = await userCollection.insertOne({
      username,
      email,
      password: hashedPassword,
      user_type: newUser.user_type // Use the default user_type value from newUser object
    });

    console.log(`User ${username} registered successfully!`);
    res.redirect('/login');
  } catch (error) {
    console.log(error);
    res.status(400).send(`Validation error: ${error.details[0].message}`);
  }
});



// LOGIN
app.get('/login', (req, res) => {
  res.render("login");
});



// Login route
app.post('/login', async (req, res) => {
  // Retrieve the username and password from the request body
  const { username, password } = req.body;

  // Retrieve the user from the database based on the username
  const user = await userCollection.findOne({ username: username });

  // Check if a user was found and if the password matches the hashed password in the database
  if (user && await bcrypt.compare(password, user.password)) {
    // If the user is an admin, set the isAdmin property in the session object to true
    if (user.user_type === 'admin') {
      req.session.isAdmin = true;
    }
    // Set the authenticated property in the session object to true
    req.session.authenticated = true;
    // Set the username property in the session object to the logged-in user's username
    req.session.username = username;
    // Redirect the user to the home page
    res.redirect('/');
  } else {
    // If the user was not found or the password did not match, display an error message
    res.render('login', { error: 'Invalid username or password' });
  }
});




// LOGGING IN
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


// Members page that only logged in users can access
app.get('/members', (req, res) => {
  const username = req.session.username;
  const image1 = "graduation.gif";
  const image2 = "yandhi.gif";
  const image3 = "kanye.gif";

  if (!username) {
    res.redirect('/login');
  } else {
    res.render('members', { username, image1, image2, image3 });
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
  res.render("404");
})

// States which port to listen on
app.listen(port, () => {
  console.log("Node application listening on port " + port);
});

