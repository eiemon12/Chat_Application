require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || "your_secret_key";

// Middleware
app.use(express.json());
app.use(cors());

// Database connection
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "",
  database: "chat_app",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// JWT Authentication Middleware
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(403).json({ message: "No token provided" });
  }

  const tokenParts = token.split(" ");
  if (tokenParts.length !== 2 || tokenParts[0] !== "Bearer") {
    return res.status(401).json({ message: "Invalid token format" });
  }

  jwt.verify(tokenParts[1], SECRET_KEY, (err, decoded) => {
    if (err) {
      console.error("Error verifying token:", err);
      return res.status(401).json({ message: "Invalid or expired token" });
    }
    req.user = decoded; // Store decoded user info
    next();
  });
};

// User Registration
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const connection = await pool.getConnection();

    // Check if user already exists
    const [existingUsers] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (existingUsers.length > 0) {
      connection.release();
      return res.status(400).json({ message: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    await connection.execute(
      "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword]
    );

    connection.release();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({ message: "An error occurred", error: error.message });
  }
});

// User Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    const connection = await pool.getConnection();

    // Check if user exists
    const [users] = await connection.execute("SELECT * FROM users WHERE email = ?", [email]);

    connection.release();

    if (users.length === 0) {
      return res.status(400).json({ message: "User not found" });
    }

    const user = users[0];

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY, {
      expiresIn: "1h",
    });

    res.json({ message: "Login successful", token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Logout Route
router.post('/logout', (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
      return res.status(400).json({ message: "No token provided" });
  }

  blacklist.add(token);

  res.json({ message: "Logged out successfully" });
});



// Protected Route - Dashboard
app.get("/dashboard", verifyToken, (req, res) => {
  res.json({ message: "Welcome to the dashboard!", user: req.user });
});

// Protected Route - Fetch All Users
app.get("/users", verifyToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [users] = await connection.execute("SELECT id, username, email FROM users");
    connection.release();

    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Error retrieving users", error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
