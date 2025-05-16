const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  outlet: [{ type: String }],
  firstName: { type: String, required: true },
  middleName: { type: String }, // Optional
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  contactNumber: { type: String, required: true },
  password: { type: String, required: true }, // Hashed
  isVerified: { type: Boolean, default: false },
});

const User = mongoose.model("User", userSchema);
module.exports = User;
