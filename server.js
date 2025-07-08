const { Pool } = require("pg");
const express = require("express");
const bcrypt = require("bcrypt");
const app = express();
const saltRounds = 10;

// Configuración de PostgreSQL (usa variables de entorno en producción)
const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ||
    "postgresql://users_z1lc_user:iUIt5TM3r8RqqGgT4FynnJ2QzqIVTSzL@dpg-d1mq0sndiees73f79qqg-a/users_z1lc",
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

// Creación de tabla al iniciar (solo en desarrollo)
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log("Database initialized");
  } catch (err) {
    console.error("Database initialization error:", err);
  }
}

initializeDatabase();

app.use(express.json());

// Middleware de validación (se mantiene igual)
const validateData = (req, res, next) => {
  /* ... (el mismo código de validación que tenías) ... */
  next();
};

// Registro de usuario
app.post("/register", validateData, async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
      [email, hashedPassword]
    );

    const newUser = result.rows[0];
    console.log(`New user registered with ID: ${newUser.id}`);

    res.status(201).json({
      success: "User registered",
      user: newUser,
    });
  } catch (err) {
    if (err.code === "23505") {
      // Código de error UNIQUE violation en PostgreSQL
      return res.status(409).json({ error: "Email already exists" });
    }
    console.error("Registration error:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
app.post("/login", validateData, async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT id, email, password FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    res.json({
      success: "Login successful",
      user: { id: user.id, email: user.email },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Restablecer contraseña
app.post("/reset-password", validateData, async (req, res) => {
  const { email, newPassword } = req.body;
  const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

  try {
    const result = await pool.query(
      "UPDATE users SET password = $1 WHERE email = $2 RETURNING id",
      [hashedPassword, email]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ success: "Password reset successful" });
  } catch (err) {
    console.error("Password reset error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Obtener todos los usuarios (solo para desarrollo)
app.get("/users", async (req, res) => {
  try {
    const result = await pool.query("SELECT id, email FROM users");
    res.json({ users: result.rows });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Reiniciar base de datos (solo para desarrollo)
app.get("/reset-db", async (req, res) => {
  if (process.env.NODE_ENV === "production") {
    return res.status(403).json({ error: "Not allowed in production" });
  }

  try {
    await pool.query("TRUNCATE TABLE users RESTART IDENTITY CASCADE");
    res.json({ success: "Database reset successful" });
  } catch (err) {
    console.error("Database reset error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
