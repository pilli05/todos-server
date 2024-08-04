const express = require("express");
const app = express();
const cors = require("cors");
const bcrypt = require("bcryptjs");
const sqlite = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const swaggerUi = require("swagger-ui-express");
const fs = require("fs");
const path = require("path");
dotenv.config();

const PORT = process.env.PORT;
const secretKey = process.env.USER_SECRET_KEY;

app.use(cors());
app.use(express.json());

const db = new sqlite.Database("./Database.db", (error) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Database connected");
  }
});

db.serialize(() => {
  db.run(
    "CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)"
  );
});

db.serialize(() => {
  db.run(
    "CREATE TABLE IF NOT EXISTS todo (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, description TEXT, status TEXT)"
  );
});

const authenticateUser = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  console.log(authHeader);
  if (token === null)
    return res
      .status(401)
      .send({ status: false, message: "Unauthorized User" });
  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res
        .status(401)
        .send({ status: false, message: "Unauthorized User" });
    } else {
      req.user = user;
      next();
    }
  });
};

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (username === "" || password === "") {
    return res
      .status(400)
      .json({ status: false, message: "Please fill in all fields" });
  }
  db.get("SELECT * FROM user WHERE username = ?", [username], (error, row) => {
    if (error) {
      return res
        .status(500)
        .json({ status: false, message: "Error checking username" });
    }
    if (row) {
      return res
        .status(409)
        .json({ status: false, message: "Username already exists" });
    } else {
      const hashedPassword = bcrypt.hashSync(password, 10);

      db.run(
        "INSERT INTO user (username, password) VALUES (?, ?)",
        [username, hashedPassword],
        (error) => {
          if (error) {
            return res.status(500).json({ message: "Error creating user" });
          }
          res.json({ status: true, message: "User created successfully" });
        }
      );
    }
  });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === "" || password === "") {
    return res
      .status(400)
      .json({ status: false, message: "Please fill in all fields" });
  }

  db.get("SELECT * FROM user WHERE username = ?", [username], (error, row) => {
    if (error) {
      return res.status(500).send({ message: "Internal Server Error" });
    }
    if (row) {
      const validPassword = bcrypt.compareSync(password, row.password);
      if (validPassword) {
        const token = jwt.sign(
          { id: row.id, username: row.username },
          secretKey,
          { expiresIn: "1h" }
        );
        return res.status(200).send({
          status: true,
          message: "Login successful",
          token: token,
          userName: row.username,
          userId: row.id,
        });
      } else {
        return res
          .status(401)
          .json({ status: false, message: "Invalid username or password" });
      }
    } else {
      return res
        .status(403)
        .send({ status: false, message: "Invalid username or password" });
    }
  });
});

app.post("/todos", authenticateUser, (req, res) => {
  const { status, description, user_id } = req.body;

  db.run(
    "INSERT INTO todo (user_id, description, status) VALUES (?, ?, ?)",
    [user_id, description, status],
    (error) => {
      if (error) {
        return res
          .status(500)
          .send({ status: false, message: "Internal Server Error" });
      }
      res.json({ status: true, message: "Todo created successfully" });
    }
  );
});

app.get("/todos", authenticateUser, (req, res) => {
  const user_id = req.user.id;
  db.all("SELECT * FROM todo WHERE user_id = ?", [user_id], (err, rows) => {
    if (err) {
      return res.status(500).send({ message: "Internal Server Error" });
    }

    res.json({ status: true, todos: rows });
  });
});

app.get("/todos/:id", authenticateUser, (req, res) => {
  const { id } = req.params;
  db.get("SELECT * FROM todo WHERE id = ?", [id], (err, row) => {
    if (err) {
      return res
        .status(500)
        .send({ status: false, message: "Internal Server Error" });
    }

    res.json({ status: true, todo: row });
  });
});

app.put("/todos/:id", authenticateUser, (req, res) => {
  const { id } = req.params;
  const { status, description } = req.body;
  db.run(
    "UPDATE todo SET description = ?, status = ? WHERE id = ?",
    [description, status, id],
    (error) => {
      if (error) {
        return res
          .status(500)
          .send({ status: false, message: "Internal Server Error" });
      }
      res.json({ status: true, message: "Todo updated successfully" });
    }
  );
});

app.delete("/todos/:id", authenticateUser, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM todo WHERE id = ?", [id], (err) => {
    if (err) {
      return res
        .status(500)
        .send({ status: false, message: "Internal Server Error" });
    }

    res.json({ status: true, message: "Todo deleted successfully" });
  });
});

const swaggerFile = path.join(__dirname, "./config/swagger-output.json");
const swaggerDocument = JSON.parse(fs.readFileSync(swaggerFile, "utf8"));

app.use("/swagger", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
