import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import express from "express";
import cors from "cors";
import pool from "./db";
import { Request, Response, NextFunction } from "express";


const JWT_SECRET = "supersecret";

const app = express();
const PORT = 4000;

//-------------------------------------------------------------------------
interface AuthRequest extends Request {
  user?: any;
}

function authenticateToken(
  req: AuthRequest,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ error: "Token required" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }

    req.user = user;
    next();
  });
}

//-------------------------------------------------------------------------

app.use(cors());
app.use(express.json());

app.get("/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({
      status: "NanoMinion API alive",
      dbTime: result.rows[0].now,
    });
  } catch (err) {
    res.status(500).json({ error: "Database connection failed" });
  }
});

app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert into DB
    const result = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at",
      [email, hashedPassword]
    );

    res.status(201).json({
      message: "User created",
      user: result.rows[0],
    });

  } catch (err: any) {
    // Handle duplicate email
    if (err.code === "23505") {
      return res.status(400).json({ error: "Email already exists" });
    }

    res.status(500).json({ error: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ message: "Login successful", token });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/me", authenticateToken, (req: AuthRequest, res) => {
  res.json({
    message: "Protected route accessed",
    user: req.user,
  });
});

app.listen(PORT, () => {
  console.log(`NanoMinion API running on port ${PORT}`);
});