const express = require('express')
const app = express()
const mysql = require('mysql')
const cors = require('cors')
const bcrypt = require('bcrypt')
const saltRounds = 10
const { v4: uuidv4 } = require('uuid')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const cookieSession = require('cookie-session')

app.use(express.json())
app.use(cookieParser())

app.set('trust proxy', 1)

app.use(cookieSession({
    name: 'session',
    keys: ["crischatkey"],
    // sameSite: 'none',
    // httpOnly: false,
    // proxy: true,
    // Cookie Options
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }))

// parse application/json
app.use(bodyParser.json())

const corsOption = {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
    credentials: true,
    optionsSuccessStatus: 200
}
app.use(cors(corsOption))

const db = mysql.createConnection({
    user: "assessmentno4",
    host: "db4free.net",
    password: "crisandro",
    database: "foneapichat",
})

app.use(session({
    key: "user",
    secret: "someRandomS3cr3ts",
    resave: false,
    saveUninitialized: false,
    proxy: true,
    // httpOnly: false,
    sameSite: 'none',
    cookie: {
        secure: true, // required for cookies to work on HTTPS
        sameSite: 'none',
        // httpOnly: false,
    }
}))

app.get('/',cors(corsOption),(req,res)=>{
    // db.query(`SELECT contacts FROM users WHERE id = 5`,
    // (err, result) =>  {
    //     //console.log(result[0].contacts.split(","))
    //     let ids = result[0].contacts.split(",")
    //     db.query(`SELECT * FROM users WHERE id IN (${ids}) `,
    //     (err, result) =>  {
    //         console.log(result)
            
    //     })
    // })
})

app.post("/api/register",cors(corsOption), (req, res) => {
    const {firstname,lastname,username,password} = req.body;

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            console.log(err);
        }
        db.query(`INSERT INTO users (id, username, password, firstname, lastname, contacts) VALUES (null, '${username}','${hash}','${firstname}','${lastname}', '')`,
        (err, result) => {
            res.send({result: `${username} has been added`})
        });
    });
});

app.post("/api/login",cors(corsOption), (req, res) => {
    const {username, password}= req.body;

    db.query(
        `SELECT * FROM users WHERE username = '${username}'`,
        (err, result) => {
            if (err) {
                res.send({ err: err });
            }

            if (result.length > 0) {
                bcrypt.compare(password, result[0].password, (error, response) => {
                if (response) {
                    req.session.user = result
                    req.session.id = uuidv4()
                    res.send({ loggedIn: true , result })
                } else {
                    res.send({ message: "Wrong username/password combination!" , loggedIn: false });
                }
                });
            } else {
                res.send({ message: "User doesn't exist" , loggedIn: false })
            }
        }
    );
});

app.get("/api/login",cors(corsOption),(req,res)=>{
    if( req.session.user ){
         res.send({ loggedIn: true, user: req.session.user })
    } else {
        res.send({ loggedIn: false })
    }
})

app.get("/api/loggedInUser",cors(corsOption),(req,res)=>{
    const {id, username, firstname, lastname} = req.session.user[0]
    res.send({id:id, username: username, firstname: firstname, lastname: lastname})
})

app.post("/api/logout",cors(corsOption),(req,res)=>{
    req.session = null
    res.send({ loggedIn: false })
})

app.get("/api/users",cors(corsOption),(req,res) => {
    db.query(`SELECT contacts FROM users WHERE id = ${req.session.user[0].id}`,
    (err, result) =>  {
        let found = false
        if( result[0].contacts === "" ){
            res.send([])
        }else{
            let ids = result[0].contacts.split(",")
            let quertIds = ids.slice(1)
            db.query(`SELECT DISTINCT users.id, firstname, lastname, username, MAX(chat.date_sent) FROM users INNER JOIN chat ON chat.firstuser_id = users.id OR chat.seconduser_id = users.id  WHERE id IN ( ${quertIds} ) GROUP BY users.id ORDER BY MAX(chat.date_sent) DESC`,
            (err, result) =>  {
                res.send(result)
            })
        }
        
    })
})

app.post("/api/send",cors(corsOption),(req,res) => {
    const {message,to} = req.body;

    db.query(`SELECT contacts FROM users WHERE id = ${req.session.user[0].id}`,
    (err, result) =>  {
        let found = false
        if( result[0].contacts === ""){
            db.query(`UPDATE users SET contacts = '${to}' WHERE id = ${req.session.user[0].id}`,
            (err, result) =>  {})
            db.query(`UPDATE users SET contacts = CONCAT(contacts,',${req.session.user[0].id}') WHERE id = ${to}`,
            (err, result) =>  {})
            db.query(`INSERT INTO chat (chat_id, chat_message, date_sent, firstuser_id, seconduser_id, view) VALUE (null, '${message}', NOW(), ${req.session.user[0].id}, ${to}, null)`,
            (err, result) => {
                res.send({message: "done"})
            })
        }else{
            let ids = result[0].contacts.split(",")
            ids.map( ids => ids != to ? found = false : found = true )
            if(found){
                db.query(`INSERT INTO chat (chat_id, chat_message, date_sent, firstuser_id, seconduser_id, view) VALUE (null, '${message}', NOW(), ${req.session.user[0].id}, ${to}, null)`,
                (err, result) => {
                    res.send({message: "done"})
                })

            }else{
                db.query(`UPDATE users SET contacts = '${result[0].contacts},${to}' WHERE id = ${req.session.user[0].id}`,
                (err, result) =>  {})
                db.query(`UPDATE users SET contacts = CONCAT(contacts,',${req.session.user[0].id}') WHERE id = ${to}`,
                (err, result) =>  {})
                db.query(`INSERT INTO chat (chat_id, chat_message, date_sent, firstuser_id, seconduser_id, view) VALUE (null, '${message}', NOW(), ${req.session.user[0].id}, ${to}, null)`,
                (err, result) => {
                    res.send({message: "done"})
                })
            }
            
        }
    })
})

app.post("/api/messages",cors(corsOption),(req,res) => {
    const {id} = req.body;
    db.query(`SELECT * FROM chat WHERE firstuser_id = ${req.session.user[0].id} OR seconduser_id = ${req.session.user[0].id} ORDER BY date_sent DESC`,
    (err, result) => {
        const finaldata = result.filter( data => data.firstuser_id === id || data.seconduser_id === id )
        res.send(finaldata)
    })
})

app.post("/api/deletemessage",cors(corsOption),(req,res) => {
    const {chat_id} = req.body;
    db.query(`DELETE FROM chat WHERE chat_id = ${chat_id}`,
    (err, result) => {})
})

app.post("/api/searchusers",cors(corsOption),(req,res) => {
    const {search} = req.body;
    db.query(`SELECT id , firstname, lastname, username FROM users WHERE NOT id = ${req.session.user[0].id} AND firstname LIKE '${search}%' OR lastname LIKE '${search}%'`,
    (err, result) => {
        res.send(result)
    })
})

const port = process.env.PORT || 3001

app.listen(port, ()=> {
    console.log("running on port 3001")
})