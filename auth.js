const jwt = require("jsonwebtoken");
require("dotenv").config(); // Ensure environment variables are loaded

module.exports = function (req, res, next) {
  // Get token from Authorization header
  const token = req.header("Authorization")?.split(" ")[1]; // This will get the token part after "Bearer"

  if (!token) {
    return res.status(401).json({ message: "No token, authorization denied" });
  }

  // Verify the token
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user; // Set user from decoded token
    next();
  } catch (err) {
    console.error("Token verification error:", err);
    res.status(401).json({ message: "Token is not valid" });
  }
};
