require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || "emon";  

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
const blacklist = new Set(); 

app.post('/logout', (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
      return res.status(400).json({ message: "No token provided" });
  }

  try {
      const decoded = jwt.verify(token, SECRET_KEY); 

      //console.log("Decoded Token:", decoded);
      blacklist.add(token);

      return res.json({ message: "Logged out successfully" });

  } catch (error) {
      console.log("JWT Error:", error);

      if (error.name === "TokenExpiredError") {
          return res.status(401).json({ message: "Token expired, please log in again" });
      } else {
          return res.status(401).json({ message: "Invalid token" });
      }
  }
});

//logout.........
app.post('/logout', (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(400).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);

    // Blacklist the token (add to a set)
    blacklist.add(token);

    return res.json({ message: "Logged out successfully" });

  } catch (error) {
    console.log("JWT Error:", error);

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token expired, please log in again" });
    } else {
      return res.status(401).json({ message: "Invalid token" });
    }
  }
});

// Middleware to check blacklisted tokens
const isBlacklisted = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (blacklist.has(token)) {
        return res.status(401).json({ message: "Token has been logged out" });
    }

    next();
};


// Get Dashboard Info (with token validation)
app.get('/dashboard', verifyToken, async (req, res) => {
  try {
      const userId = req.user.userId; 
      const username = req.user.username; 

      // Get total number of users in the database
      const connection = await pool.getConnection();
      const [totalUsers] = await connection.execute("SELECT COUNT(*) AS count FROM users");
      connection.release();

      res.json({ username, totalUsers: totalUsers[0].count-1 });
  } catch (error) {
      console.error("Error retrieving dashboard data:", error);
      return res.status(500).json({ message: "Error retrieving dashboard data", error: error.message });
  }
});

//chat list........

app.get('/chat-list', verifyToken, async (req, res) => {
  try {
      // Get the logged-in user's ID (from JWT token)
      const loggedInUserId = req.user.userId;

      // Fetch all users (except the logged-in user)
      const connection = await pool.getConnection();
      const [users] = await connection.execute("SELECT * FROM users WHERE id != ?", [loggedInUserId]);
      connection.release();

      res.json({ users });
  } catch (error) {
      console.error('Error fetching chat list:', error);
      res.status(500).json({ message: 'Failed to fetch chat list' });
  }
});



//message(._.)
app.post('/send-message', verifyToken, async (req, res) => {
  const { receiver_id, message } = req.body;
  
  if (!receiver_id || !message) {
      return res.status(400).json({ message: "Receiver and message are required." });
  }

  try {
      const sender_id = req.user.userId; // Get logged-in user's ID from the token

      const connection = await pool.getConnection();
      
      // Insert message into the database
      await connection.execute(
          "INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)",
          [sender_id, receiver_id, message]
      );
      
      connection.release();
      res.status(200).json({ message: "Message sent successfully." });

  } catch (error) {
      console.error("Error sending message:", error);
      res.status(500).json({ message: "Failed to send message." });
  }
});


app.get('/messages/:userId', verifyToken, async (req, res) => {
  const otherUserId = req.params.userId;
  
  try {
      const sender_id = req.user.userId; // Get logged-in user's ID from the token
      
      const connection = await pool.getConnection();
      
      // Fetch all messages between the logged-in user and the other user
      const [messages] = await connection.execute(
          `SELECT m.*, u1.username AS sender, u2.username AS receiver
           FROM messages m
           JOIN users u1 ON m.sender_id = u1.id
           JOIN users u2 ON m.receiver_id = u2.id
           WHERE (m.sender_id = ? AND m.receiver_id = ?)
              OR (m.sender_id = ? AND m.receiver_id = ?)
           ORDER BY m.timestamp`,
          [sender_id, otherUserId, otherUserId, sender_id]
      );
      
      connection.release();
      res.json({ messages });

  } catch (error) {
      console.error("Error fetching messages:", error);
      res.status(500).json({ message: "Failed to fetch messages." });
  }
});


///group routes


app.post('/create-group', verifyToken, async (req, res) => {
  const { groupName } = req.body; // Extracting groupName from body
  const userId = req.user?.userId; // Extracting userId from JWT token

  if (!groupName || !userId) {
    return res.status(400).json({ message: 'Group name and user ID are required' });
  }

  try {
    const connection = await pool.getConnection();

    // Insert group into the database
    const createGroupQuery = `
      INSERT INTO groups (name, created_by)
      VALUES (?, ?)
    `;
    
    const [results] = await connection.execute(createGroupQuery, [groupName, userId]);

    connection.release();
    
    res.status(201).json({ message: 'Group created successfully', groupId: results.insertId });
  } catch (err) {
    console.error('Error creating group:', err);
    res.status(500).json({ message: 'Error creating group' });
  }
});



// Join Group
app.post('/group/:groupId/join', verifyToken, async (req, res) => {
  const { groupId } = req.params;
  const userId = req.user.id;

  try {
      const query = 'INSERT INTO group_members (group_chat_id, user_id) VALUES (?, ?)';
      await pool.execute(query, [groupId, userId]);
      res.status(200).json({ message: 'Joined group' });
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
  }
});

// Get Group Messages
app.get('/group/:groupId/messages', verifyToken, async (req, res) => {
  const { groupId } = req.params;

  try {
      const query = 'SELECT * FROM group_messages WHERE group_chat_id = ? ORDER BY sent_at DESC';
      const [messages] = await pool.execute(query, [groupId]);
      res.status(200).json(messages);
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
  }
});

// Send Group Message
app.post('/group/:groupId/messages', verifyToken, async (req, res) => {
  const { groupId } = req.params;
  const { message } = req.body;
  const senderId = req.user.id;

  if (!message) return res.status(400).json({ message: 'Message is required' });

  try {
      const query = 'INSERT INTO group_messages (group_chat_id, sender_id, message) VALUES (?, ?, ?)';
      await pool.execute(query, [groupId, senderId, message]);
      res.status(201).json({ message: 'Message sent' });
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
  }
});

// Leave Group
app.delete('/group/:groupId/leave', verifyToken, async (req, res) => {
  const { groupId } = req.params;
  const userId = req.user.id;

  try {
      const query = 'DELETE FROM group_members WHERE group_chat_id = ? AND user_id = ?';
      const [result] = await pool.execute(query, [groupId, userId]);

      if (result.affectedRows === 0) {
          return res.status(404).json({ message: 'You are not a member of this group' });
      }

      res.status(200).json({ message: 'You have left the group' });
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
  }
});



app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
