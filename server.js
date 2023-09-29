

const express = require('express');
const path = require('path');
const bodyParser = require("body-parser");
const passwordHash = require('password-hash');
const session = require('express-session');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const serviceAccount = require("./key.json");

initializeApp({
  credential: cert(serviceAccount)
});
const db = getFirestore();

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: '!@#$%', 
  resave: false,
  saveUninitialized: true
}));

app.set('view engine', 'ejs');
app.use(express.static('public'));

app.get('/signup', function (req, res) {
  res.sendFile(__dirname + "/public/" + "signup.html");
});

app.get('/login', function (req, res) {
  const successMessage = req.session.successMessage || null;
  res.render('login', { successMessage });
});





app.post('/signupsubmit', function (req, res) {
  const email = req.body.email;

  // Check if the email already exists in the collection
  db.collection('login-details')
    .where("Email", "==", email)
    .get()
    .then((docs) => {
      if (!docs.empty) {
        res.send("<center><h1>Sorry, this account already exists with this email</h1></center>");
      } else {
        const hashedPassword = passwordHash.generate(req.body.password); // Use the hashed password from user input
        db.collection('login-details').add({
          Firstname: req.body.firstname,
          Email: req.body.email,
          Password: hashedPassword, // Store the hashed password in Firestore
          Confirmpassword: hashedPassword // Store the hashed password in Firestore
        })
          .then(() => {
            res.redirect('/login');
          })
          .catch(error => {
            console.error("Error adding document: ", error);
            res.status(500).send("Error signing up");
          });
      }
    })
    .catch(error => {
      console.error("Error querying Firestore: ", error);
      res.status(500).send("Error signing up");
    });
});

app.get('/logout', function (req, res) {
  // Clear the user's session to log them out
  req.session.destroy(function(err) {
    if (err) {
      console.error('Error destroying session:', err);
      res.status(500).send('Error logging out');
    } else {
      // Redirect the user to the login page after logout
      res.redirect('/login');
    }
  });
});

app.post('/loginsubmit', function (req, res) {
  const email = req.body.email;
  const password = req.body.password;

  db.collection('login-details').get()
    .then((docs) => {
      let dataPres = false;
      docs.forEach((doc) => {
        if (email == doc.data().Email && passwordHash.verify(password, doc.data().Password)) {
          dataPres = true;
        }
      });

      if (dataPres) {
        res.redirect("nutritionhub.html");
      } else {
        res.send("data not present in Firebase, please login");
      }
    })
    .catch(error => {
      console.error("Error querying Firestore: ", error);
      res.status(500).send("Error logging in");
    });
});

app.listen(3000,function(){
    console.log("listening to the server on http://localhost:3000/signup");
  });
