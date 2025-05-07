const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const Inventory = require("./inventoryProcess");
const bcrypt = require("bcryptjs");
const User = require("./users");
const authMiddleware = require("./auth");
const jwt = require("jsonwebtoken");
require("dotenv").config();

// MongoDB Atlas connection
const uri =
  "mongodb+srv://NewClientApp:NewClientAppPass@towi.v2djp3n.mongodb.net/ReactTOWI?retryWrites=true&w=majority&appName=TOWI";

mongoose
  .connect(uri)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// INVENTORY

app.post("/inventory/grouped", async (req, res) => {
  try {
    const inventoryData = req.body;
    const newInventory = await Inventory.create(inventoryData);

    res.status(201).json({
      success: true,
      data: newInventory,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Error saving inventory",
    });
  }
});

// INVENTORY LOCK

app.post("/lock", async (req, res) => {
  try {
    const { inventoryId, locked } = req.body;

    // Validate input
    if (!inventoryId || typeof locked !== "boolean") {
      return res.status(400).json({
        success: false,
        message: "inventoryId (string) and locked (boolean) are required",
      });
    }

    // Verify inventory exists first
    const inventory = await Inventory.findById(inventoryId);
    if (!inventory) {
      return res.status(404).json({
        success: false,
        message: "Inventory not found",
      });
    }

    // Prevent locking if already in desired state
    if (inventory.locked === locked) {
      return res.json({
        success: true,
        message: `Inventory already ${locked ? "locked" : "unlocked"}`,
        data: inventory,
      });
    }

    // Update lock status
    const updatedInventory = await Inventory.findByIdAndUpdate(
      inventoryId,
      { locked },
      { new: true, runValidators: true }
    );

    res.json({
      success: true,
      message: `Inventory ${locked ? "locked" : "unlocked"} successfully`,
      data: updatedInventory,
    });
  } catch (error) {
    console.error("Error updating lock status:", error);
    res.status(500).json({
      success: false,
      message: "Server error updating lock status",
      error: error.message,
    });
  }
});

// INVENTORY HISTORY

app.get("/inventoryHistory", async (req, res) => {
  try {
    const inventories = await Inventory.find();
    res.json(inventories);
  } catch (error) {
    console.error("❌ Error fetching inventory:", error);
    res.status(500).json({ message: "Failed to fetch inventory" });
  }
});

//SIGN UP

app.post("/signup", async (req, res) => {
  try {
    const {
      firstName,
      middleName,
      lastName,
      email,
      contactNumber,
      username,
      password,
    } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already taken" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      firstName,
      middleName,
      lastName,
      email,
      contactNumber,
      username,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("❌ Error signing up:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

//PROFILE

app.get("/profile", authMiddleware, async (req, res) => {
  try {
    // req.user is set by authMiddleware after verifying token
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(user);
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

//LOGIN

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Create JWT Payload
    const payload = {
      user: {
        id: user.id,
      },
    };

    // Sign Token
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: "5h" },
      (err, token) => {
        if (err) throw err;
        res.json({
          token,
          user: {
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
          },
        });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server error" });
  }
});

// Auth

app.get("/auth", authMiddleware, async (req, res) => {
  try {
    // req.user is set by authMiddleware after verifying token
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(user);
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});
