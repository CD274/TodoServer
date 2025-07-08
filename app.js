const sqlite3 = require("sqlite3").verbose();
const express = require("express");
const bcrypt = require("bcrypt");
const app = express();
const saltRounds = 10;

const db = new sqlite3.Database("./users.db", (err) => {
  if (err) {
    return console.error(err.message);
  }
  console.log("Connected to the database.");
  db.run(`
    CREATE TABLE IF NOT EXISTS user (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password TEXT
    )
  `);
});

app.use(express.json());

const validateData = (req, res, next) => {
  const { email, password, newPassword } = req.body;

  // Validación de campo email
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res
      .status(400)
      .json({ error: "Please enter a valid email address" });
  }

  // Seleccionar cuál contraseña validar
  const passToValidate = password || newPassword;

  if (!passToValidate) {
    return res.status(400).json({ error: "Password is required" });
  }

  const passwordErrors = [];

  if (passToValidate.length < 8) {
    passwordErrors.push("Password must be at least 8 characters long");
  }

  if (!/[A-Z]/.test(passToValidate)) {
    passwordErrors.push("Password must contain at least one uppercase letter");
  }

  if (!/[a-z]/.test(passToValidate)) {
    passwordErrors.push("Password must contain at least one lowercase letter");
  }

  if (!/[0-9]/.test(passToValidate)) {
    passwordErrors.push("Password must contain at least one number");
  }

  if (!/[!@#$%^&*(),.?":{}|<>]/.test(passToValidate)) {
    passwordErrors.push("Password must contain at least one special character");
  }

  if (passwordErrors.length > 0) {
    return res.status(400).json({
      error: "Password does not meet requirements",
      details: passwordErrors,
    });
  }

  next();
};

// Registro de usuario (con hashing de contraseña)
app.post("/register", validateData, async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const sqlInsert = `INSERT INTO user (email, password) VALUES (?, ?)`;
    const sqlSelect = `SELECT * FROM user WHERE id = ?`;

    db.run(sqlInsert, [email, hashedPassword], function (err) {
      if (err) {
        if (err.message.includes("UNIQUE constraint failed")) {
          return res.status(409).json({ error: "Email already exists" });
        }
        return res.status(500).json({ error: "Registration failed" });
      }

      const newUserId = this.lastID;

      // Ahora obtenemos el usuario completo recién creado
      db.get(sqlSelect, [newUserId], (err, row) => {
        if (err) {
          console.error("Error fetching new user:", err);
          return res.status(500).json({
            error: "Registration successful but failed to retrieve user data",
          });
        }

        console.log(`A new user has been registered with ID: ${newUserId}`);
        res.status(201).json({
          success: "User registered",
          user: row, // Devolvemos el objeto completo del usuario
        });
      });
    });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Login (con comparación de contraseñas hasheadas)
app.post("/login", validateData, (req, res) => {
  const { email, password } = req.body;
  const sql = `SELECT * FROM user WHERE email = ?`;

  db.get(sql, [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: "Server error" });
    }
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    res.json({
      success: "Login successful",
      user: { id: user.id, email: user.email },
    });
  });
});
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;
  const sql = `SELECT * FROM user WHERE email = ?`;

  db.get(sql, [email], (err, user) => {
    if (err) {
      return res.status(500).json({ error: "Server error" });
    }
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({ success: "Your email is valid" });
  });
});
app.post("/reset-password", validateData, (req, res) => {
  const { email, newPassword } = req.body;
  const sql = `UPDATE user SET password = ? WHERE email = ?`;
  const hashedPassword = bcrypt.hashSync(newPassword, saltRounds);
  try {
    db.run(sql, [hashedPassword, email], (err) => {
      if (err) {
        return res.status(500).json({ error: "Server error" });
      }
      res.json({ success: "Password reset successful" });
    });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});
app.get("/users", (req, res) => {
  const sql = `SELECT * FROM user`;
  db.all(sql, (err, users) => {
    if (err) {
      return res.status(500).json({ error: "Server error" });
    }
    res.json({ users });
  });
});
app.get("/reset-base", (req, res) => {
  const sql = `DELETE FROM user`;
  db.run(sql, (err) => {
    if (err) {
      return res.status(500).json({ error: "Server error" });
    }
    res.json({ success: "Database reset successful" });
  });
});
app.listen(3000, "0.0.0.0", () => {
  console.log("Server is running on port 3000");
});
