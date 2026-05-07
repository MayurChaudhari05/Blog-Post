const express = require("express");
let app = express();
let path = require("path");
app.use(express.urlencoded({ extended: true }));

const { v4: uuidv4 } = require('uuid');
var methodOverride = require('method-override');
app.use(methodOverride('_method'));

const mysql = require("mysql2");
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: "blog_db",
    password: "process.env.DB_PASS"
});

// Connect DB
connection.connect((err) => {
    if (err) {
        console.log("Error connecting:", err);
    } else {
        console.log("Connected to MySQL");
    }
});


const session = require("express-session");

app.use(session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: false
}));


app.use((req, res, next) => {
    res.locals.currentUserId = req.session.userId;
    next();
});

const bcrypt = require("bcrypt");

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.post("/register", async (req, res) => {
    let { email, password } = req.body;

    if (!email || !password) {
        return res.send("All fields required");
    }

    let hashedPassword = await bcrypt.hash(password, 10);
    let id = uuidv4();

    const sql = "INSERT INTO users (id, email, password) VALUES (?, ?, ?)";

    connection.query(sql, [id, email, hashedPassword], (err) => {
        if (err) {
            console.log(err);
            return res.send("Error registering user");
        }
        res.redirect("/login");
    });
});


app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.post("/login", (req, res) => {
    let { email, password } = req.body;

    const sql = "SELECT * FROM users WHERE email = ?";

    connection.query(sql, [email], async (err, results) => {
        if (err) return res.send("Error");

        if (results.length === 0) {
            return res.send("User not found");
        }

        let user = results[0];

        let isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.send("Invalid password");
        }

     
        req.session.userId = user.id;

        res.redirect("/");
    });
});


app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/login");
});


function isLoggedIn(req, res, next) {
    if (!req.session.userId) {
        return res.redirect("/login");
    }
    next();
}



app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));





app.get("/", isLoggedIn, (req, res) => {
    let query = "SELECT * FROM posts";

    connection.query(query, (err, results) => {
        if (err) {
            console.log(err);
            return res.status(500).send("Database error");
        }
        res.render("index.ejs", { posts: results });
    });
});



app.get("/posts/new", isLoggedIn, (req, res) => {
    res.render("new.ejs");
});



app.post("/posts", isLoggedIn, (req, res) => {
    let id = uuidv4();
    let { title, content } = req.body;
    let user_id = req.session.userId; // Get logged in user's ID

   
    if (!title || !content) {
        return res.send("All fields are required");
    }

    const sql = "INSERT INTO posts (id, title, content, user_id) VALUES (?, ?, ?, ?)";

    connection.query(sql, [id, title, content, user_id], (err) => {
        if (err) {
            console.log(err);
            return res.send("Error inserting data");
        }
        res.redirect('/');
    });
});


app.get("/posts/:id", isLoggedIn, (req, res) => {
    let { id } = req.params;
    let query = "SELECT * FROM posts WHERE id = ?";

    connection.query(query, [id], (err, results) => {
        if (err) return res.send("Error fetching post");
        if (results.length === 0) return res.send("Post not found");

        res.render("show.ejs", { post: results[0] });
    });
});

app.get("/posts/:id/edit", isLoggedIn, (req, res) => {
    let { id } = req.params;
    let query = "SELECT * FROM posts WHERE id = ?";

    connection.query(query, [id], (err, results) => {
        if (err) return res.send("Error fetching post");
        if (results.length === 0) return res.send("Post not found");

        let post = results[0];

        
        if (post.user_id !== req.session.userId) {
            return res.status(403).send("Unauthorized: You can only edit your own posts.");
        }

        res.render("edit.ejs", { post });
    });
});


app.patch("/posts/:id", isLoggedIn, (req, res) => {
    let { id } = req.params;
    let { content } = req.body;

    
    const checkOwnerSql = "SELECT user_id FROM posts WHERE id = ?";
    connection.query(checkOwnerSql, [id], (err, results) => {
        if (err || results.length === 0) return res.send("Error finding post");
        
        if (results[0].user_id !== req.session.userId) {
            return res.status(403).send("Unauthorized: You can only update your own posts.");
        }

        const updateSql = "UPDATE posts SET content = ? WHERE id = ?";
        connection.query(updateSql, [content, id], (err) => {
            if (err) return res.send("Error updating post");
            res.redirect('/');
        });
    });
});


app.delete("/posts/:id", isLoggedIn, (req, res) => {
    let { id } = req.params;


    const checkOwnerSql = "SELECT user_id FROM posts WHERE id = ?";
    connection.query(checkOwnerSql, [id], (err, results) => {
        if (err || results.length === 0) return res.send("Error finding post");
        
        if (results[0].user_id !== req.session.userId) {
            return res.status(403).send("Unauthorized: You can only delete your own posts.");
        }

        const deleteSql = "DELETE FROM posts WHERE id = ?";
        connection.query(deleteSql, [id], (err) => {
            if (err) return res.send("Error deleting post");
            res.redirect('/');
        });
    });
});


const port = 3000;
app.listen(port, () => {
    console.log("Server started on port", port);
});

