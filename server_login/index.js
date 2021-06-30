const express = require("express");

const cors = require("cors");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const  bodyParser = require("body-parser");
const cookieParser = require("cookie-parser")
const  session = require("express-session")

const mysql = require("mysql");
const { response } = require("express");


const jwt = require('jsonwebtoken')




const app = express();
app.use(express.json());


app.use(cookieParser())
app.use(bodyParser.urlencoded({ extended: true }))

app.use(cors({
  origin:["http://localhost:3000"],
  methods:["GET","POST"],
  credentials: true
}));
app.use(session({
  key:"userId",
  secret:"subscribe",
  resave:false,
  saveUninitialized:false,
  cookie:{
    expires: 60*60*24,

  }
}))

const db = mysql.createConnection({
  user: "root",
  host: "localhost",
  password: "password",
  database: "LoginSystem",
});

app.post("/register", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.log(err);
    }
    db.query(
      "INSERT INTO userdata (username,password) VALUES (?,?)",
      [username, hash],
      (err, result) => {
        console.log(err);
      }
    );
  });
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  db.query(
    "SELECT * FROM userdata WHERE username= ?",
    username,
    (err, result) => {
      if (err) {
        res.send({ err: err });
      }

      if (result.length > 0) {
        console.log("result", result);
        bcrypt.compare(password, result[0].password, (error, response) => {
          console.log(response);
          if (response) {
            // req.session.user = result
            // console.log(req.session.user);
 
            const id = result[0].id
            const token =jwt.sign({id},"jwtSecret",{
              expiresIn: 300,
            })

            req.session.user = result
            res.json({auth:true, token:token, result:result});
          } else {
            res.json({ auth:false , message:"Wrong Username/ Password Combination!" });
          }
        });
      } else {
        res.json({auth:false, message:"No User Exists"});
      }
    }
  );
});


const verifyJWT =(req,res,next)=>{
 const token = req.headers["x-access-token"]
 if(!token){
    res.send("Yo,we need a token, please give it to us next time!")
 }
 else{
   jwt.verify(token,"jwtSecret",(err,decoded)=>{
     if(err){
       res.json({auth:false,message:"you failed to authenticate"})
     }
     else{
       req.userId = decoded.id;
       next();
     }
   })
 }
}


app.get("/isUserAuth",verifyJWT ,(req,res)=>{
  res.send("Yo, u are authenticated Congrats!")
})


app.get("/login",(req,res)=>{
  if(req.session.user){
    res.send({loggedIn: true, user: req.session.user})
  }else{
    res.send({loggedIn: false})
  }
})







app.get("/get", (req, res) => {
  console.log("aarti");
  res.send("aartip");
});

app.listen(3002, () => {
  console.log("running server 3001");
});
