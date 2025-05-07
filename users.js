const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  middleName: { type: String }, // Optional
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  contactNumber: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Hashed
});

const User = mongoose.model("User", userSchema);
module.exports = User;
