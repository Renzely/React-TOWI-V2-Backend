const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const AWS = require("aws-sdk");
const app = express();
app.use(cors());
app.use(express.json());
const Attendance = require("./attendance");
const Inventory = require("./inventoryProcess");
const bcrypt = require("bcryptjs");
const User = require("./users");
const AdminUser = require("./adminUsers");
const authMiddleware = require("./auth");
const auth = require("./auth");
const jwt = require("jsonwebtoken");
const { DateTime } = require("luxon");
require("dotenv").config();

const nodemailer = require("nodemailer");
const Otp = require("./otp");

// MongoDB Atlas connection
const uri = process.env.uri;

mongoose
  .connect(uri)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ATTENDANCE

const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
});

app.post("/save-attendance-images", (req, res) => {
  const { fileName } = req.body;

  const params = {
    Bucket: "towi-react-attendance",
    Key: fileName,
    Expires: 60,
    ContentType: "image/jpeg",
  };

  s3.getSignedUrl("putObject", params, (err, url) => {
    if (err) {
      return res
        .status(500)
        .json({ error: "Failed to generate pre-signed URL" });
    }

    res.json({ url });
  });
});

function createPhilippineDate(dateStr) {
  const date = new Date(dateStr);
  const year = date.getFullYear();
  const month = date.getMonth();
  const day = date.getDate();

  // Create date at midnight Philippine time
  const isoString = `${year}-${String(month + 1).padStart(2, "0")}-${String(
    day
  ).padStart(2, "0")}T00:00:00.000+08:00`;
  return new Date(isoString);
}

app.put("/forgot-password-reset", async (req, res) => {
  const { password, emailAddress } = req.body;

  const encryptedPassword = await bcrypt.hash(password, 8);

  console.log(emailAddress);
  try {
    await AdminUser.findOneAndUpdate(
      { emailAddress: emailAddress },
      { $set: { password: encryptedPassword } }
    );
    res.send({ status: 200, data: "Password updated" });
  } catch (error) {
    res.send({ status: "error", data: error });
  }
});

app.post("/send-otp-forgotpassword", async (req, res) => {
  const { emailAddress } = req.body;

  const oldUser = await AdminUser.findOne({ emailAddress: emailAddress });

  if (!oldUser) {
    return res.status(404).json({ error: "Email does not exist" });
  }

  try {
    var code = Math.floor(100000 + Math.random() * 900000);
    code = String(code);
    code = code.substring(0, 4);

    const info = await transporter.sendMail({
      from: {
        name: "BMPower",
        address: process.env.Email,
      },
      to: emailAddress,
      subject: "OTP code",
      html:
        "<b>Your OTP code is</b> " +
        code +
        "<b>. Do not share this code with others.</b>",
    });

    return res.status(200).json({
      status: 200,
      data: info,
      emailAddress: emailAddress,
      code: code,
    });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ error: "Failed to send OTP. Please try again." });
  }
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) return res.status(404).json({ message: "User not found" });

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Save OTP in the Otp collection with purpose "reset-password"
    await Otp.create({
      email,
      otp,
      purpose: "reset-password",
      createdAt: new Date(),
    });

    // Send OTP via email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP is: ${otp}`,
    });

    res.status(200).json({ message: "OTP sent to email" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to send OTP" });
  }
});

app.post("/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: "Password has been reset successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Reset failed" });
  }
});

app.get("/user/outlets", auth, async (req, res) => {
  try {
    const userEmail = req.user.email; // Make sure this comes from decoded token

    if (!userEmail)
      return res.status(400).json({ error: "Missing user email" });

    const user = await User.findOne({ email: userEmail });

    if (!user) return res.status(404).json({ error: "User not found" });

    res.json(user.outlet || []);
  } catch (error) {
    console.error("Error in /user/outlets:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/attendance/status", async (req, res) => {
  const { email, outlet, date } = req.query;
  try {
    // Use the same createPhilippineDate function from your time-in/time-out endpoints
    const dateObj = createPhilippineDate(date);
    const attendance = await Attendance.findOne({ email, date: dateObj });

    if (!attendance) {
      return res.json({
        hasTimedIn: false,
        hasTimedOut: false,
        timeInTimestamp: null,
        timeOutTimestamp: null,
        addressTimeIn: null,
        addressTimeOut: null,
        timeInSelfieUri: null,
        timeOutSelfieUri: null,
      });
    }

    // Assuming attendance.timeLogs is an array of logs for outlets and timestamps
    const log = attendance.timeLogs.find((log) => log.outlet === outlet);
    if (!log) {
      return res.json({
        hasTimedIn: false,
        hasTimedOut: false,
        timeInTimestamp: null,
        timeOutTimestamp: null,
        addressTimeIn: null,
        addressTimeOut: null,
        timeInSelfieUri: null,
        timeOutSelfieUri: null,
      });
    }

    return res.json({
      hasTimedIn: !!log.timeIn,
      hasTimedOut: !!log.timeOut,
      timeInTimestamp: log.timeIn || null,
      timeOutTimestamp: log.timeOut || null,
      addressTimeIn: log.timeInLocation || null,
      addressTimeOut: log.timeOutLocation || null,
      timeInSelfieUri: log.timeInSelfieUrl || null,
      timeOutSelfieUri: log.timeOutSelfieUrl || null,
    });
  } catch (err) {
    console.error("Error fetching attendance status:", err);
    return res.status(500).json({ error: "Failed to fetch attendance status" });
  }
});

app.get("/attendance/history", async (req, res) => {
  const { email } = req.query;
  try {
    const attendanceList = await Attendance.find({ email }).sort({ date: -1 });

    const history = attendanceList.map((attendance) => {
      return {
        date: attendance.date,
        timeLogs: attendance.timeLogs.map((log) => ({
          outlet: log.outlet,
          timeIn: log.timeIn,
          timeOut: log.timeOut,
          addressTimeIn: log.timeInLocation,
          addressTimeOut: log.timeOutLocation,
          timeInSelfieUri: log.timeInSelfieUrl,
          timeOutSelfieUri: log.timeOutSelfieUrl,
        })),
      };
    });

    res.json(history);
  } catch (err) {
    console.error("Error fetching attendance history:", err);
    res.status(500).json({ error: "Failed to fetch attendance history" });
  }
});

app.post("/get-attendance", async (req, res) => {
  try {
    const { email, startDate, endDate } = req.body;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Email required" });
    }

    const range = {};
    if (startDate) range.$gte = new Date(`${startDate}T00:00:00.000Z`);
    if (endDate) range.$lte = new Date(`${endDate}T23:59:59.999Z`);

    const query = { email };
    if (Object.keys(range).length) query.createdAt = range;

    const records = await Attendance.find(query).sort({ createdAt: 1 });

    if (!records.length) {
      return res.json({ success: true, data: [] });
    }

    let counter = 1;
    const flat = records.flatMap((att) =>
      att.timeLogs.map((log) => ({
        count: counter++,
        email: att.email,
        // keep the original human‑readable string for UI
        date: att.date,

        outlet: log.outlet ?? "",
        timeIn: log.timeIn ?? null,
        timeOut: log.timeOut ?? null,

        hasTimedIn: Boolean(log.timeIn),
        hasTimedOut: Boolean(log.timeOut),

        timeInLocation: log.timeInLocation ?? "No location provided",
        timeOutLocation: log.timeOutLocation ?? "No location provided",

        timeInCoordinates: log.timeInCoordinates ?? {
          latitude: 0,
          longitude: 0,
        },
        timeOutCoordinates: log.timeOutCoordinates ?? {
          latitude: 0,
          longitude: 0,
        },

        timeInSelfieUrl: log.timeInSelfieUrl ?? "",
        timeOutSelfieUrl: log.timeOutSelfieUrl ?? "",
      }))
    );

    res.json({ success: true, data: flat });
  } catch (err) {
    console.error("Error in /get-attendance:", err);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Route to handle time-in
app.post("/attendance/time-in", async (req, res) => {
  try {
    const {
      email,
      date,
      outlet,
      timeIn,
      selfieUrl,
      location,
      timeInLocation, // accept from client
    } = req.body;

    if (
      !email ||
      !date ||
      !outlet ||
      !timeIn ||
      !selfieUrl ||
      !location?.latitude ||
      !location?.longitude
    ) {
      return res.status(400).json({ error: "Missing required fields." });
    }

    const philippineNow = DateTime.now().setZone("Asia/Manila");
    const dateObj = philippineNow.startOf("day").toJSDate(); // e.g. 2025-06-20T00:00:00
    const timeInObj = philippineNow.toJSDate(); // current full timestamp

    let attendance = await Attendance.findOne({ email, date: dateObj });

    const timeLog = {
      outlet,
      timeIn: timeInObj,
      // use timeInLocation if provided, else fallback to coordinates string
      timeInLocation:
        timeInLocation ||
        `Lat: ${location.latitude}, Long: ${location.longitude}`,
      timeInCoordinates: {
        latitude: location.latitude,
        longitude: location.longitude,
      },
      timeInSelfieUrl: selfieUrl,
    };

    if (attendance) {
      attendance.timeLogs.push(timeLog);
    } else {
      attendance = new Attendance({
        email,
        date: dateObj,
        timeLogs: [timeLog],
      });
    }

    await attendance.save();
    return res.status(200).json({ message: "Time-in recorded successfully." });
  } catch (error) {
    console.error("Time-in error:", error);
    return res.status(500).json({ error: "Failed to save time-in." });
  }
});

// Route to handle time-out
app.post("/attendance/time-out", async (req, res) => {
  try {
    const {
      email,
      date,
      outlet,
      timeOut,
      timeOutSelfieUrl,
      location,
      timeOutLocation, // accept from client
    } = req.body;

    if (
      !email ||
      !date ||
      !outlet ||
      !timeOut ||
      !timeOutSelfieUrl ||
      !location?.latitude ||
      !location?.longitude
    ) {
      return res.status(400).json({ error: "Missing required fields." });
    }

    const philippineNow = DateTime.now().setZone("Asia/Manila");
    const dateObj = philippineNow.startOf("day").toJSDate(); // e.g. 2025-06-20T00:00:00
    const timeOutObj = philippineNow.toJSDate();

    const attendance = await Attendance.findOne({ email, date: dateObj });

    if (!attendance) {
      return res.status(404).json({ error: "Attendance record not found." });
    }

    const lastTimeLog = [...attendance.timeLogs]
      .reverse()
      .find((log) => log.outlet === outlet && !log.timeOut);

    if (!lastTimeLog) {
      return res.status(404).json({
        error: "No corresponding time-in record found for this outlet.",
      });
    }

    lastTimeLog.timeOut = timeOutObj;
    // use timeOutLocation if provided, else fallback to coordinates string
    lastTimeLog.timeOutLocation =
      timeOutLocation ||
      `Lat: ${location.latitude}, Long: ${location.longitude}`;
    lastTimeLog.timeOutCoordinates = {
      latitude: location.latitude,
      longitude: location.longitude,
    };
    lastTimeLog.timeOutSelfieUrl = timeOutSelfieUrl;

    await attendance.save();
    return res.status(200).json({ message: "Time-out recorded successfully." });
  } catch (error) {
    console.error("Time-out error:", error);
    return res.status(500).json({ error: "Failed to save time-out." });
  }
});

// INVENTORY

app.post("/inventory/grouped", async (req, res) => {
  try {
    const {
      email,
      date,
      merchandiser,
      outlet,
      weeksCovered,
      month,
      week,
      versions,
    } = req.body;

    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Missing userEmail" });
    }

    const newInventory = await Inventory.create({
      email,
      date,
      merchandiser,
      outlet,
      weeksCovered,
      month,
      week,
      versions,
    });

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

app.get("/", (req, res) => {
  res.json({ status: "started" });
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

// INVENTORY FETCH FOR ADMIN

app.post("/retrieve-inventory-data", async (req, res) => {
  try {
    const { outlet } = req.body;

    if (!outlet || !Array.isArray(outlet)) {
      return res.status(400).json({ message: "Invalid branch list." });
    }

    const inventoryData = await Inventory.find({
      outlet: { $in: outlet },
    });

    res.json({ success: true, data: inventoryData });
  } catch (error) {
    console.error("Error retrieving inventory:", error);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

// DATE PICKER

app.post("/filter-date-range", async (req, res) => {
  const { startDate, endDate } = req.body;
  console.log("Filter range:", { startDate, endDate });

  try {
    const inventoryInRange = await Inventory.find({
      date: { $gte: startDate, $lte: endDate },
    });

    console.log("Found inventory in range:", inventoryInRange);
    return res.status(200).json({ status: 200, data: inventoryInRange });
  } catch (error) {
    console.error("Error fetching inventory:", error);
    return res.status(500).send({ error: "Internal Server Error" });
  }
});

app.post("/export-inventory-towi", async (req, res) => {
  const { start, end } = req.body;

  try {
    const data = await Inventory.aggregate([
      {
        $match: {
          $expr: {
            $and: [
              { $gte: [{ $toDate: "$date" }, new Date(start)] },
              { $lt: [{ $toDate: "$date" }, new Date(end)] },
            ],
          },
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "email",
          foreignField: "email",
          as: "user_details",
        },
      },
      {
        $unwind: {
          path: "$user_details",
          preserveNullAndEmptyArrays: true,
        },
      },
      {
        $project: {
          date: 1,
          merchandiser: 1,
          outlet: 1,
          weeksCovered: 1,
          month: 1,
          week: 1,
          locked: 1,
          versions: 1,
        },
      },
    ]);

    const formatted = [];

    data.forEach((record, index) => {
      ["V1", "V2", "V3"].forEach((versionKey) => {
        const version = record.versions?.[versionKey];
        if (!version) return;

        ["Carried", "Not Carried", "Delisted"].forEach((status) => {
          const skuList = version[status] || [];

          skuList.forEach((sku) => {
            formatted.push({
              count: formatted.length + 1,
              date: record.date,
              fullname: record.merchandiser || "N/A",
              outlet: record.outlet,
              weeksCovered: record.weeksCovered,
              month: record.month,
              week: record.week,
              sku: sku.sku,
              skuCode: sku.skuCode,
              status,
              beginning:
                status === "Carried"
                  ? sku.beginningPCS || 0
                  : status === "Not Carried"
                  ? "NC"
                  : "Delisted",
              delivery: status === "Carried" ? sku.deliveryPCS || 0 : "",
              ending: status === "Carried" ? sku.endingPCS || 0 : "",
              offtake: status === "Carried" ? sku.offtake || 0 : "",
              inventoryDaysLevel:
                status === "Carried" ? sku.inventoryDays || 0 : "",
              expiryMonth: status === "Carried" ? sku.expiryMonths || "" : "",
              expiryQty: status === "Carried" ? sku.expiryQty || 0 : "",
            });
          });
        });
      });
    });

    return res.send({ status: 200, data: formatted });
  } catch (error) {
    console.error("Error exporting inventory data:", error);
    return res.status(500).send({ error: error.message });
  }
});

// INVENTORY HISTORY

app.get("/inventoryHistory", async (req, res) => {
  const { email } = req.query; // e.g., ?email=user@example.com

  try {
    const inventories = await Inventory.find({ email: email }); // Use correct field
    res.json(inventories);
  } catch (error) {
    console.error("❌ Error fetching inventory:", error);
    res.status(500).json({ message: "Failed to fetch inventory" });
  }
});

// ADMIN USERS

app.post("/get-admin-user", async (req, res) => {
  try {
    const users = await AdminUser.find(); // Returns all documents and fields
    return res.send({ status: 200, data: users });
  } catch (error) {
    return res.status(500).send({ error: error.message });
  }
});

// ADMIN REGISTRATION

app.post("/register-user-admin", async (req, res) => {
  const {
    firstName,
    middleName,
    lastName,
    emailAddress,
    contactNum,
    password,
    roleAccount,
    outlet,
    remarks,
  } = req.body;

  try {
    // Check if user already exists
    const existingUser = await AdminUser.findOne({ emailAddress });
    if (existingUser) {
      return res.send({ status: "error", message: "User already exists!" });
    }

    // Encrypt password
    const encryptedPassword = await bcrypt.hash(password, 8);

    // Determine type based on role (you can adjust logic if needed)
    // let type = 3; // Default type
    // if (roleAccount === "Admin") {
    //   type = 1;
    // }

    // Create new user
    const newUser = await AdminUser.create({
      firstName,
      middleName,
      lastName,
      emailAddress,
      contactNum,
      password: encryptedPassword,
      roleAccount,
      remarks: remarks || "",
      isVerified: false,
      outlet: outlet || [],
      // type,
    });

    res.send({ status: 200, message: "Admin user registered", user: newUser });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).send({ status: "error", message: error.message });
  }
});

// ADMIN USER OTP

app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  try {
    var code = Math.floor(100000 + Math.random() * 900000);
    code = String(code);
    code = code.substring(0, 4);

    const info = await transporter.sendMail({
      from: {
        name: "BMPower",
        address: process.env.EMAIL_USER,
      },
      to: email,
      subject: "OTP code",
      html:
        "<b>Your OTP code is</b> " +
        code +
        "<b>. Do not share this code with others.</b>",
    });

    return res.send({ status: 200, code: code });
  } catch (error) {
    return res.send({ error: error.message });
  }
});

// ADMIN USER UPDATE STATUS

app.put("/update-admin-status", async (req, res) => {
  const { isVerified, emailAddress } = req.body;

  try {
    const updatedUser = await AdminUser.findOneAndUpdate(
      { emailAddress },
      { $set: { isVerified: isVerified } },
      { new: true }
    );

    if (!updatedUser) {
      return res
        .status(404)
        .send({ status: "error", message: "User not found" });
    }

    res.send({ status: 200, message: "Status updated", user: updatedUser });
  } catch (error) {
    res.status(500).send({ status: "error", message: error.message });
  }
});

// ADMIN USER UPDATE OUTLET

app.put("/update-admin-outlet", async (req, res) => {
  const { emailAddress, outlet } = req.body;

  try {
    const updatedUser = await AdminUser.findOneAndUpdate(
      { emailAddress },
      { $set: { outlet } },
      { new: true }
    );

    if (!updatedUser) {
      return res
        .status(404)
        .send({ status: "error", message: "User not found" });
    }

    res.send({
      status: 200,
      message: "User branches updated",
      user: updatedUser,
    });
  } catch (error) {
    res.status(500).send({ status: "error", message: error.message });
  }
});

// USERS

app.post("/get-all-user", async (req, res) => {
  try {
    const users = await User.find(); // No projection — returns all fields
    return res.send({ status: 200, data: users });
  } catch (error) {
    return res.status(500).send({ error: error.message });
  }
});

// UPDATE USERS OUTLET
app.put("/update-user-branch", async (req, res) => {
  const { email, outlet } = req.body;

  try {
    const updatedUser = await User.findOneAndUpdate(
      { email },
      { $set: { outlet } }, // No need to join, just save the array
      { new: true }
    );

    if (!updatedUser) {
      return res
        .status(404)
        .send({ status: "error", message: "User not found" });
    }

    res.send({ status: 200, data: "User branches updated", user: updatedUser });
  } catch (error) {
    res.status(500).send({ status: "error", message: error.message });
  }
});

// ADMIN LOGIN

app.post("/login-admin", async (req, res) => {
  const { emailAddress, password } = req.body;

  try {
    const user = await AdminUser.findOne({ emailAddress });

    if (!user) {
      return res.status(401).json({
        status: 401,
        data: "Email address not found",
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        status: 401,
        data: "Incorrect password",
      });
    }

    // Login success
    return res.status(200).json({
      status: 200,
      data: {
        firstName: user.firstName,
        lastName: user.lastName,
        roleAccount: user.roleAccount,
        outlet: user.outlet,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      status: 500,
      data: "Internal server error",
    });
  }
});

//SIGN UP

app.post("/signup", async (req, res) => {
  const {
    outlet,
    firstName,
    middleName,
    lastName,
    email,
    contactNumber,
    password,
  } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: "Email already registered" });
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create new user with isVerified set to false
  const newUser = new User({
    outlet,
    firstName,
    middleName,
    lastName,
    email,
    contactNumber,
    password: hashedPassword,
    isVerified: false,
  });

  await newUser.save();

  // Generate and send OTP (6 digits only)
  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generates a 6-digit number
  const newOtp = new Otp({ email, otp });
  await newOtp.save();
  await sendEmail(
    email,
    "Your OTP Code",
    `Your OTP is ${otp}. It will expire in 5 minutes.`
  );

  res.status(201).json({ message: "User registered. OTP sent to email." });
});

app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  // Find the OTP entry
  const otpEntry = await Otp.findOne({ email, otp });
  if (!otpEntry) {
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }

  // Mark user as verified
  await User.updateOne({ email }, { isVerified: true });

  // Delete the OTP entry
  await Otp.deleteOne({ _id: otpEntry._id });

  res.status(200).json({ message: "Email verified successfully" });
});

const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const sendEmail = async (to, subject, text) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    text,
  };
  await transporter.sendMail(mailOptions);
};

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
        email: user.email,
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
            outlet: user.outlet,
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
