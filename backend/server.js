const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const connectDB = require("./config/db");

const authRoutes = require("./routes/authRoutes");

dotenv.config({ path: __dirname + "/.env" });

const app = express();

app.use(express.json());

app.use(cors({
  origin: "http://localhost:5173"
}));

app.get("/health", (req, res) => {
  res.json({
    status: "healthy"
  });
});

app.use("/api/auth", authRoutes);

const PORT = process.env.PORT || 5000;

if (require.main === module) {
  connectDB();

  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

module.exports = app;