

const gift_dev_msg = "Gift from Liquem Games. Have fun!";
const coinsmin = 80
const coinsmax = 120
const lobbytheme = 3
const rarity_normal = 0.8 //0.8
const rarity_legendary = 0.995 //0.995
const allgadgets = 3
const friendMax = 30

// configurations
   
const express = require("express");
const { MongoClient, ServerApiVersion } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const cors = require("cors");
const cron = require("node-cron");
const Discord = require("discord.js");
const timeout = require("connect-timeout");
const helmet = require("helmet");
const bodyParser = require("body-parser");
const fs = require("fs");
const readline = require("readline");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const EventEmitter = require('events');
const mongoSanitize = require('express-mongo-sanitize');
const http = require('http');
const compression = require('compression');


const webhookURL = process.env.DISCORD_KEY;
const tokenkey = process.env.TOKEN_KEY;

const eventEmitter = new EventEmitter();

const webhook = new Discord.WebhookClient({
          url: webhookURL,
        });

const app = express();
exports.app = app;


const port = process.env.PORT || 3000;
//const http = require('http').createServer(app);





const MAX_REQUEST_SIZE = 1000;
const MAX_PARAM_BODY_LENGTH = 200;

const requestTimeoutMs = 5000;

// Set trust proxy to true if the app is behind a proxy

// Set up middleware for JSON and URL-encoded form data parsing with limits

// Middleware to check request size


process.on("SIGINT", function () {
  mongoose.connection.close(function () {
    console.log("Mongoose disconnected on app termination");
    process.exit(0);
  });
});

const whitelist = [
  '3.134.238.10',
  '3.129.111.220',
  '52.15.118.168',
  '3.75.158.163',
  '3.125.183.140',
  '35.157.117.28',
  '13.228.225.19',
  '18.142.128.26',
  '54.254.162.138'
];

const getClientIp = (req) => {
  return req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
};

const verifychangeserver = (req, res, next) => {
  const clientIp = getClientIp(req);
  if (whitelist.includes(clientIp)) {
    next();
  } else {
    res.status(403).send('not verified');
  }
};

/*const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 20,
  message: "lg_server_limit_reached",
});
*/


const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 second window
  max: 45,
  message: 'lg_server_limit_reached',
  keyGenerator: function(req) { return req.headers['true-client-ip'] || req.headers['x-forwarded-for'] },
  handler: (req, res) => res.status(429).json({ message: 'lg_server_limit_reached' }),
});


const noexploit = rateLimit({
  windowMs: 1000, // 1 second window
  max: 5,
  message: 'lg_server_limit_reached',
  keyGenerator: function(req) { return req.headers['true-client-ip'] || req.headers['x-forwarded-for'] },
  handler: (req, res) => res.status(429).json({ message: 'lg_server_limit_reached' }),
});

const registerLimiter = rateLimit({
  windowMs: 1 * 30 * 1000,
  max: 10,
  keyGenerator: function(req) { return req.headers['true-client-ip'] || req.headers['x-forwarded-for'] },
  message: "Zu viele Registrierungsanfragen von dieser IP-Adresse, bitte versuche es später erneut.",
});

const accountCreationLimit = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 24 hours
  max: 1, // Max 1 request per IP per day
  keyGenerator: function(req) { return req.headers['true-client-ip'] || req.headers['x-forwarded-for'] },
  message: "Sie haben bereits die maximale Anzahl von Benutzerkonten für heute erstellt.",
});



const allowedOrigins = [
   "https://uploads.ungrounded.net",
  "https://slcount.netlify.app",
  "https://s-r.netlify.app",
  "https://serve.gamejolt.net",
  "null",
  "tw-editor://.",
  "http://serve.gamejolt.net",
  "https://www.newgrounds.com/portal/view/5561763",
  "https://www.newgrounds.com/projects/games/5561763/preview",
  "https://prod-dpgames.crazygames.com",
  "https://crazygames.com",
   "https://crazygames.com/game/skilled-royale",
   "https://html-classic.itch.zone",
   "https://turbowarp.org",
   "https://s-ri0p-delgae.netlify.app",
];



app.use((req, res, next) => {
  const origin = req.headers.origin;
   
  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    next();
  } else {
    console.log("Rejected request from:", origin);
    return res.status(403).json({ error: "no contents" });
  }
});

//app.use(compression());
app.use(noexploit);
app.use(limiter);
app.set("trust proxy", true);
app.use(cors());
app.use(bodyParser.json());
app.use(express.json());

app.use(express.json({ limit: '1b' }));
app.use(express.urlencoded({ extended: true, limit: '1b' }));
app.use(timeout('5s'));


app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        fontSrc: ["'self'"],
        imgSrc: ["'none'"],
        connectSrc: ["'none'"],
        frameSrc: ["'none'"],
        mediaSrc: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    hsts: {
      maxAge: 31536000, // 1 year in seconds
      includeSubDomains: true,
      preload: true,
    },
    contentSecurityPolicy: false,
    poweredBy: false,
    hidePoweredBy: true,
    xssFilter: true,
    frameguard: { action: "deny" },
    expectCt: true,
    dnsPrefetchControl: { allow: false },
    referrerPolicy: { policy: "same-origin" },
    featurePolicy: {
      features: {
        geolocation: ["'none'"],
      },
    },
    permittedCrossDomainPolicies: { permittedPolicies: "none" },
    noSniff: true,
    permissionsPolicy: {
      features: {
        accelerometer: ["'none'"],
        camera: ["'none'"],
        microphone: ["'none'"],
        geolocation: ["'none'"],
      },
    },
  }),
);


const sanitizeInputs = (inputs) => {
  if (typeof inputs === "object" && inputs !== null) {
    if (Array.isArray(inputs)) {
      return inputs.every((item) => sanitizeInputs(item));
    } else {
      for (const key in inputs) {
        if (inputs.hasOwnProperty(key)) {
          if (key.includes('$')) {
            return false; // Invalid input
          }
          if (!sanitizeInputs(inputs[key])) {
            return false; // Invalid nested input
          }
        }
      }
      return true; // Valid input
    }
  } else if (typeof inputs === "string") {
    // Perform string sanitization
    return true; // All strings are considered valid after sanitization
  }
  return true; // Primitive values are considered valid
};


// Use the timeout middleware for all routes
//app.use(timeout(requestTimeoutMs));

process.on("SIGINT", function () {
  mongoose.connection.close(function () {
    console.log("Mongoose disconnected on app termination");
    process.exit(0);
  });
});



let maintenanceMode = false;
// Middleware, um Wartungsarbeiten zu überprüfen
function checkMaintenanceMode(req, res, next) {
  if (maintenanceMode) {
    return res.status(503).send("Wartung");
  }
  next();
}

app.post('/toggle-maintenance', (req, res) => {
    maintenanceMode = true;
    // Emit maintenance event
    //eventEmitter.emit('maintenanceMode', { maintenanceMode });
    res.json({ maintenanceMode });
});

app.post('/disable-maintenance', (req, res) => {
    maintenanceMode = false;
    // Emit maintenance event
    //eventEmitter.emit('maintenance', { maintenanceMode });
    res.json({ maintenanceMode });
});

app.use(checkMaintenanceMode);


/*const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});



rl.on("line", (input) => {
  const command = input.trim().toLowerCase();
  if (command === "mt on") {
    maintenanceMode = true;
    console.log("Wartungsarbeiten sind jetzt aktiviert.");
  } else if (command === "mt off") {
    maintenanceMode = false;
    console.log("Wartungsarbeiten sind jetzt deaktiviert.");
  } else {
    console.log(
      'Invalid command. Use "/maintenance off or /maintenance on" or "exit" to quit.',
    );
  }
});
*/

// Replace <password> with the actual password for the Liquem user
const password = process.env.DB_KEY
const encodedPassword = encodeURIComponent(password);

const uri = `mongodb+srv://Liquem:${encodedPassword}@cluster0.ed4zami.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
    socketTimeoutMS: 30000,
 //   maxConnecting: 2,
   // maxIdleTimeMS: 300000,
   // maxPoolSize: 100,
    //minPoolSize: 0,
  },
});

async function startServer() {
  try {
    // Connect to the MongoDB server
    await client.connect();
  
    console.log("Connected to MongoDB");

    // Start the express server
   
  } catch (err) {
    console.error("Error connecting to MongoDB:", err);
  }
}

startServer();

// MongoDB User Schema
const db = client.db("Cluster0");
const userCollection = db.collection("users");
const friendsCollection = db.collection("friends");
const PackItemsCollection = db.collection("packitems");
const battlePassCollection = db.collection("battlepass_users");
const loginRewardsCollection = db.collection("onetime_rewards");
const shopcollection = db.collection("ShopCollection");


const usernameRegex = /^(?!.*(&[a-zA-Z0-9]+;|<|>|\/|\\|\s)).{4,16}$/u;
const passwordRegex = /^(?!.*(&[a-zA-Z0-9]+;|<|>|\/|\\|\s)).{4,20}$/u;

//const usernameRegex = /^(?!.*(&[a-zA-Z0-9]+;|<|>|\/|\\|\s)).{4,16}$/u;

//const passwordRegex = /^(?!.*(&[a-zA-Z0-9]+;|<|>|\/|\\))(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[\S]{8,20}$/;


const applyAccountCreationLimit = (req, res, next) => {
  accountCreationLimit(req, res, next);
};

app.post("/register", checkRequestSize, registerLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    let finalCountryCode = "Unknown"; // Initialize with the default value

    if (!username || !password) {
      res.status(400).send("Both username and password are required");
      return;
    }

   if (username === password) {
      res.status(400).send("identical types");
      return;
    }
     

    if (!usernameRegex.test(username)) {
      res
        .status(400)
        .send(
          "Invalid username",
        );
      return;
    }

    if (!passwordRegex.test(password)) {
      res
        .status(400)
        .send(
          "Invalid password",
        );
      return;
    }

     const existingUser = await userCollection.findOne(
      { username: { $regex: new RegExp(`^${username}$`, "i") } },
      { projection: { _id: 0, username: 1 } },
    );

    if (existingUser) {
      res.status(409).send("Username already taken");
      return;
    }

    // Use getCountryCode function to get the country code based on the user's IP address
    try {
      const countryCode = await getCountryCode(req.ip);
      finalCountryCode = countryCode || finalCountryCode; // Update only if countryCode is truthy
    } catch (error) {
      console.error("Error getting country code:", error.message);
    }

    // Check account creation limit here
        const hashedPassword = await bcrypt.hash(password, 10);
        const token = jwt.sign({ username }, tokenkey);
        const currentTimestamp = new Date();

        applyAccountCreationLimit(req, res, async () => {

           try {

        await userCollection.insertOne({
          _id: username,
          username,
          password: hashedPassword,
          coins: 100,
          created_at: currentTimestamp,
          country_code: finalCountryCode,
          token,
          last_collected: 0,
          items: [],

        });


        const joinedMessage = `${username} joined Skilled Legends.`;
        webhook.send(joinedMessage);

        res.status(201).json({ token });
      } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

// Login route
app.post("/login", checkRequestSize, registerLimiter, async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await userCollection.findOne(
      { _id: username },
      { projection: { username: 1, password: 1 } },
    );

    if (!user) {
      res.status(401).send("Invalid username or password");
      return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      res.status(401).send("Invalid username or password");
      return;
    }

    // Generate a token
    const token = jwt.sign({ username: user.username }, tokenkey);

    // Save the token to the user document
    await userCollection.updateOne({ _id: username }, { $set: { token } });

    res.json({ token });
  } catch (error) {
    res.status(500).send("Internal Server Error");
  }
});

app.get("/get-coins/:token", checkRequestSize, verifyToken, async (req, res) => {
  const token = req.params.token;
  const username = req.user.username;

  try {
    session = client.startSession();
    session.startTransaction();

    // Check if the user exists in the database
    const user = await userCollection.findOne(
      { _id: username },
      { projection: { _id: 0, username: 1, last_collected: 1 } },
    );

    if (!user) {
      res.status(401).send("Invalid username or password");
      return;
    }

    // Check if enough time has passed since the last coin collection
    const lastCollected = user.last_collected;

    if (!canCollectCoins(lastCollected)) {
      res.status(400).send("You can collect coins only once every 24 hours.");
      return;
    }

    // Generate a random number of coins to add
    const coinsToAdd = generateRandomNumber(coinsmin, coinsmax);

    // Update user data in the database
    const updateResult = await userCollection.updateOne(
      { _id: username },
      {
        $inc: { coins: coinsToAdd },
        $set: { last_collected: Date.now() },
      },
    );

    await session.commitTransaction();

    if (updateResult.modifiedCount !== 1) {
      res.status(500).send("Failed to update user data");
      return;
    }

    // Send a Discord webhook notification
    //const coinsMessage = `${username} has received ${coinsToAdd} Coins.`;
    //const webhook = new Discord.WebhookClient({ url: webhookURL });
    //webhook.send(coinsMessage);

    res.json({
      message: `You have received ${coinsToAdd} Coins.`,
      coins: coinsToAdd,
      timestamp: Date.now(),
    });

  } catch (error) {
    res.status(500).send("Internal Server Error");
    await session.abortTransaction();
  }

  await session.endSession();
});

// Route zum Abrufen der aktuellen Tagesrotation
app.get("/daily-items/:token", checkRequestSize, verifyToken, async (req, res) => {
  const token = req.params.token;
  const currentDate = new Date();
  currentDate.setHours(0, 0, 0, 0);
  const t0am = currentDate.getTime();

  try {
    // Find the daily items in the shop
     const dailyItems = "dailyItems";
    const itemshop = await shopcollection.findOne({ _id: dailyItems });

     if (!itemshop) {
      return res.status(404).json({ message: "Daily items not found or empty." });
    }

    res.json({
      dailyItems: itemshop.items, // Or items directly if you don't need an array
      shoptheme: itemshop.theme,
      server_nexttime: t0am
    });
  } catch (error) {
    console.error("Error fetching daily items:", error);
    res.status(500).json({ message: "Internal Server Error." });
  }
});



app.post("/buy-item/:token/:itemId", checkRequestSize, verifyToken, async (req, res) => {
  const { itemId } = req.params;
  const username = req.user.username;

  let session;

  try {
    session = client.startSession();
    session.startTransaction();

const user = await userCollection.findOne(
  { 
    username, 
    items: { 
      $exists: true, 
      $elemMatch: { $eq: itemId } 
    } 
  }
 );

     if (user) {
      return res.status(401).json({ message: "You already own this item." });
    }


     
    const userRow = await userCollection.findOne(
      { username: username },
      {
        projection: {
          coins: 1,
        },
      },
    );
 

    const itemshop = await shopcollection.findOne({ _id: "dailyItems" });
     
   const selectedItem = Object.values(itemshop.items).find(i => i.itemId === itemId);

    if (!selectedItem) {
      return res.status(401).json({ message: "Item is not valid." });
      }

    if ((userRow.coins || 0) < selectedItem.price) {
      return res
        .status(401)
        .json({ message: "Not enough coins to buy the item." });
    }

    await session.commitTransaction();

    // Update the user's coins and add the purchased item to the items array
    await userCollection.updateOne(
      { _id: username },
      {
        $inc: { coins: -selectedItem.price },
        $push: { items: itemId },
      },
      { session },
    );

    res.json({ message: `Du hast ${selectedItem.name} gekauft.` });
  } catch (error) {
    await session.abortTransaction();
    console.error("Transaction aborted:", error);
    res.status(500).json({ message: "Internal Server Error." });
  } finally {
    if (session) {
      session.endSession();
    }
  }
});


app.post("/equip-gadget/:token/:gadget", checkRequestSize, verifyToken, async (req, res) => {
  const { gadget } = req.params;
  const username = req.user.username;

 const gadgetNumber = parseInt(gadget, 10);
  if (isNaN(gadgetNumber) || gadgetNumber < 1 || gadgetNumber > allgadgets) {
    return res.status(400).json({ message: "Invalid gadget ID." });
  }


  try {
    const result = await userCollection.updateOne(
      { _id: username },
      { $set: { equipped_gadget: gadget } },
    );

    if (result.modifiedCount === 1) {
      res.json({
        message: `success`,
        gadget: gadget,
      });
    } else {
      res.status(500).json({ message: "Failed to update gadget." });
    }
  } catch (error) {
    console.error("Error:", error);
    res
      .status(500)
      .json({ message: "Internal Server Error while equipping" });
  }
});

app.post("/equip-item1/:token/:itemid", checkRequestSize, verifyToken, async (req, res) => {
  const { itemid } = req.params;
  const token = req.params.token;
  const username = req.user.username;

  // Check if the first letter of the item ID is 'A'
  if (itemid.charAt(0).toUpperCase() !== "A") {
    return res.status(400).json({ error: "cant equip" });
  }

  try {
    const user = await userCollection.findOne(
      { username, items: { $elemMatch: { $eq: itemid } } }
    );

    if (!user) {
      return res.status(404).json({ error: "Ungültige Anmeldeinformationen oder Item nicht gefunden." });
    }

    // Equip the item by updating the equipped_item field
    await userCollection.updateOne(
      { _id: username },
      { $set: { equipped_item: itemid } },
    );

    return res.json({
      message: `success`,
    });
  } catch (error) {
    return res.status(500).json({ error: "Interner Serverfehler." });
  }
});

app.post("/equip-item2/:token/:itemid", checkRequestSize, verifyToken, async (req, res) => {
  const { itemid } = req.params;
  const token = req.params.token;
  const username = req.user.username;

  // Check if the first letter of the item ID is 'A'
  if (itemid.charAt(0).toUpperCase() !== "B") {
    return res.status(400).json({ error: "cant equip" });
  }

  try {
    const user = await userCollection.findOne(
      { username, items: { $elemMatch: { $eq: itemid } } }
    );

    if (!user) {
      return res.status(404).json({ error: "Ungültige Anmeldeinformationen oder Item nicht gefunden." });
    }

    // Equip the item by updating the equipped_item field
    await userCollection.updateOne(
      { _id: username },
      { $set: { equipped_item2: itemid } },
    );

    return res.json({
      message: `success`,
    });
  } catch (error) {
    return res.status(500).json({ error: "Interner Serverfehler." });
  }
});

app.post("/equip-banner/:token/:itemid", checkRequestSize, verifyToken, async (req, res) => {
 const { itemid } = req.params;
  const token = req.params.token;
  const username = req.user.username;

  // Check if the first letter of the item ID is 'A'
  if (itemid.charAt(0).toUpperCase() !== "I") {
    return res.status(400).json({ error: "cant equip" });
  }

  try {
    const user = await userCollection.findOne(
      { username, items: { $elemMatch: { $eq: itemid } } }
    );

    if (!user) {
      return res.status(404).json({ error: "Ungültige Anmeldeinformationen oder Item nicht gefunden." });
    }

    // Equip the item by updating the equipped_item field
    await userCollection.updateOne(
      { _id: username },
      { $set: { equipped_banner: itemid } },
    );

    return res.json({
      message: `success`,
    });
  } catch (error) {
    return res.status(500).json({ error: "Interner Serverfehler." });
  }
});

app.post("/equip-pose/:token/:itemid", checkRequestSize, verifyToken, async (req, res) => {
  const { itemid } = req.params;
  const token = req.params.token;
  const username = req.user.username;

  // Check if the first letter of the item ID is 'A'
  if (itemid.charAt(0).toUpperCase() !== "P") {
    return res.status(400).json({ error: "cant equip" });
  }

  try {
    const user = await userCollection.findOne(
      { username, items: { $elemMatch: { $eq: itemid } } }
    );

    if (!user) {
      return res.status(404).json({ error: "Ungültige Anmeldeinformationen oder Item nicht gefunden." });
    }

    // Equip the item by updating the equipped_item field
    await userCollection.updateOne(
      { _id: username },
      { $set: { equipped_pose: itemid } },
    );

    return res.json({
      message: `success`,
    });
  } catch (error) {
    return res.status(500).json({ error: "Interner Serverfehler." });
  }
});

app.post("/equip-color/:token/:color", checkRequestSize, verifyToken, async (req, res) => {
  const { color } = req.params;
  const username = req.user.username;

  const parsedColor = parseInt(color, 10);
  if (isNaN(parsedColor) || parsedColor < -400 || parsedColor > 400) {
    return res
      .status(400)
      .json({ message: "Color must be a number between -200 and 200." });
  }

  try {
    const result = await userCollection.updateOne(
      { _id: username },
      { $set: { equipped_color: parsedColor } },
    );

    if (result.modifiedCount === 1) {
      res.json({
        message: `You have successfully equipped color ${parsedColor}.`,
        equipped_color: parsedColor,
      });
    } else {
      res.status(500).json({ message: "Failed to update color." });
    }
  } catch (error) {
    console.error("Error:", error);
    res
      .status(500)
      .json({ message: "Internal Server Error while equipping color." });
  }
});

app.post("/equip-hat-color/:token/:color", checkRequestSize, verifyToken, async (req, res) => {
  const { color } = req.params;
  const username = req.user.username;

  const parsedColor = parseInt(color, 10);
  if (isNaN(parsedColor) || parsedColor < -400 || parsedColor > 400) {
    return res
      .status(400)
      .json({ message: "Color must be a number between -200 and 200." });
  }

  try {
    const result = await userCollection.updateOne(
      { _id: username },
      { $set: { equipped_hat_color: parsedColor } },
    );

    if (result.modifiedCount === 1) {
      res.json({
        message: `You have successfully equipped color ${parsedColor}.`,
        equipped_color: parsedColor,
      });
    } else {
      res.status(500).json({ message: "Failed to update color." });
    }
  } catch (error) {
    console.error("Error:", error);
    res
      .status(500)
      .json({ message: "Internal Server Error while equipping color." });
  }
});

app.post("/equip-body-color/:token/:color", checkRequestSize, verifyToken, async (req, res) => {
  const { color } = req.params;
  const username = req.user.username;

  const parsedColor = parseInt(color, 10);
  if (isNaN(parsedColor) || parsedColor < -400 || parsedColor > 400) {
    return res
      .status(400)
      .json({ message: "Color must be a number between -200 and 200." });
  }

  try {
    const result = await userCollection.updateOne(
      { _id: username },
      { $set: { equipped_body_color: parsedColor } },
    );

    if (result.modifiedCount === 1) {
      res.json({
        message: `You have successfully equipped color ${parsedColor}.`,
        equipped_color: parsedColor,
      });
    } else {
      res.status(500).json({ message: "Failed to update color." });
    }
  } catch (error) {
    console.error("Error:", error);
    res
      .status(500)
      .json({ message: "Internal Server Error while equipping color." });
  }
});

app.post("/equip-banner-color/:token/:color", checkRequestSize, verifyToken, async (req, res) => {
  const { color } = req.params;
  const username = req.user.username;

  const parsedColor = parseInt(color, 10);
  if (isNaN(parsedColor) || parsedColor < -400 || parsedColor > 400) {
    return res
      .status(400)
      .json({ message: "Color must be a number between -200 and 200." });
  }

  try {
    const result = await userCollection.updateOne(
      { _id: username },
      { $set: { equipped_banner_color: parsedColor } },
    );

    if (result.modifiedCount === 1) {
      res.json({
        message: `You have successfully equipped color ${parsedColor}.`,
        equipped_color: parsedColor,
      });
    } else {
      res.status(500).json({ message: "Failed to update color." });
    }
  } catch (error) {
    console.error("Error:", error);
    res
      .status(500)
      .json({ message: "Internal Server Error while equipping color." });
  }
});



app.post("/reset-equipped-items/:token", checkRequestSize, verifyToken, async (req, res) => {
  const username = req.user.username;

  try {
    const result = await userCollection.updateOne(
      { _id: username },
      {
        $set: {
          equipped_item: 0,
          equipped_item2: 0,
          equipped_banner: 0,
          equipped_pose: 0,
          equipped_color: 0,
          equipped_hat_color: 0,
          equipped_body_color: 0,
          equipped_banner_color: 0,
        },
      },
    );

    if (result.modifiedCount === 1) {
      res.json({
        message: "Equipped items have been reset successfully.",
      });
    } else {
      res.status(500).json({
        message: "Failed to reset equipped items. User not found.",
      });
    }
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({
      message: "Internal Server Error while resetting equipped items.",
    });
  }
});

app.get("/get-user-inventory/:token", checkRequestSize, verifyToken, async (req, res) => {


  const token = req.params.token;
  const username = req.user.username;

  try {
    const [userRow, bpuserRow, onetimeRow] = await Promise.all([
      userCollection.findOne(
        { _id: username },
        {
          projection: {
            coins: 1,
            boxes: 1,
            sp: 1,
            items: 1,
            last_collected: 1,
            equipped_item: 1,
            equipped_item2: 1,
            equipped_banner: 1,
            equipped_pose: 1,
            equipped_color: 1,
            equipped_hat_color: 1,
            equipped_body_color: 1,
            equipped_banner_color: 1,
            equipped_gadget: 1,
          }
        }
      ),
      battlePassCollection.findOne(
        { _id: username },
        {
          projection: {
            currentTier: 1,
            season_coins: 1,
            bonusitem_damage: 1,
          }
        }
      ).catch(() => null),
      loginRewardsCollection.findOne(
        { _id: username },
        {
          projection: {
            username: 1
          }
        }
      ).catch(() => null)
    ]);

    if (!userRow) {
    //  return res.status(401).json({ message: "login expired" });
         res.status(401).send("expired");
    }

    const currentTimestampInGMT = new Date().getTime();

    const currentDate = new Date();
    currentDate.setHours(0, 0, 0, 0);
    const currentTimestamp0am = currentDate.getTime();

    const onetimereward = onetimeRow ? onetimeRow.username || 0 : 0;
    const slpasstier = bpuserRow ? bpuserRow.currentTier || 0 : 0;
    const season_coins = bpuserRow ? bpuserRow.season_coins || 0 : 0;
    const bonusitem_damage = bpuserRow ? bpuserRow.bonusitem_damage || 0 : 0;

    const response = {
      coins: userRow.coins || 0,
      boxes: userRow.boxes || 0,
      sp: userRow.sp || 0,
      items: userRow.items || [], 
      slpasstier: slpasstier || 0,
      season_coins: season_coins || 0,
      bonusitem_damage: bonusitem_damage || 0,
      last_collected: userRow.last_collected || 0,
      equipped_item: userRow.equipped_item || 0,
      equipped_item2: userRow.equipped_item2 || 0,
      equipped_banner: userRow.equipped_banner || 0,
      equipped_pose: userRow.equipped_pose || 0,
      equipped_color: userRow.equipped_color || 0,
      equipped_hat_color: userRow.equipped_hat_color || 0,
      equipped_body_color: userRow.equipped_body_color || 0,
      equipped_banner_color: userRow.equipped_banner_color || 0,
      equipped_gadget: userRow.equipped_gadget || 1,
      server_timestamp: currentTimestampInGMT,
      server_nexttime: currentTimestamp0am,
      lbtheme: lobbytheme, // Assuming lobbytheme is defined elsewhere
      onetimereward: onetimereward,
    };

    res.json(response);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Interner Serverfehler." });
  }
});


app.get("/get-matchstats/:token", checkRequestSize, verifyToken, async (req, res) => {

  const token = req.params.token;
  const username = req.user.username;

  try {
    const [userRow, bpuserRow] = await Promise.all([
      userCollection.findOne(
        { _id: username },
        {
          projection: {
            coins: 1,
            sp: 1,
          }
        }
      ),
      battlePassCollection.findOne(
        { _id: username },
        {
          projection: {
            season_coins: 1,
            bonusitem_damage: 1,
          }
        }
      ).catch(() => null),
    ]);

    if (!userRow) {
      return res.status(401).json({ message: "invalid token" });
    }

    const currentDate = new Date();
    currentDate.setHours(0, 0, 0, 0);

    const season_coins = bpuserRow ? bpuserRow.season_coins || 0 : 0;
    const bonusitem_damage = bpuserRow ? bpuserRow.bonusitem_damage || 0 : 0;

    const response = {
      coins: userRow.coins || 0,
      sp: userRow.sp || 0,
      season_coins: season_coins || 0,
      bonusitem_damage: bonusitem_damage || 0,
      lbtheme: lobbytheme, // Assuming lobbytheme is defined elsewhere
    };

    res.json(response);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "server error" });
  }
});


app.get("/user-profile/:token/:usernamed", checkRequestSize, verifyToken, async (req, res) => {
  const { usernamed } = req.params;

  try {
    const userRow = await userCollection.findOne(
      { _id: usernamed },
      {
        projection: {
          equipped_item: 1,
          equipped_item2: 1,
          equipped_banner: 1,
          equipped_pose: 1,
          equipped_color: 1,
          all_coins_earned: 1,
          equipped_hat_color: 1,
          equipped_body_color: 1,
          equipped_banner_color: 1,
          created_at: 1,
          kills: 1,
          damage: 1,
          wins: 1,
          sp: 1
          // country_code: 1, // Uncomment if country_code is needed
        },
      },
    );

    if (!userRow) {
      return res.status(404).json({ message: "user not found" });
    }

    const joinedTimestamp = userRow.created_at.getTime();
    const currentTime = new Date().getTime();
    const timeSinceJoined = currentTime - joinedTimestamp;

    const daysSinceJoined = Math.floor(timeSinceJoined / (1000 * 60 * 60 * 24));
    const monthsSinceJoined = Math.floor(daysSinceJoined / 30);
    const yearsSinceJoined = Math.floor(monthsSinceJoined / 12);

    let displayString;

    if (yearsSinceJoined > 0) {
      displayString = `${yearsSinceJoined} year${yearsSinceJoined > 1 ? "s" : ""}`;
    } else if (monthsSinceJoined > 0) {
      displayString = `${monthsSinceJoined} month${monthsSinceJoined > 1 ? "s" : ""}`;
    } else {
      displayString = `${daysSinceJoined} day${daysSinceJoined > 1 ? "s" : ""}`;
    }

    res.json({
      equipped_item: userRow.equipped_item || 0,
      equipped_item2: userRow.equipped_item2 || 0,
      equipped_banner: userRow.equipped_banner || 0,
      equipped_pose: userRow.equipped_pose || 0,
      equipped_color: userRow.equipped_color || 0,
      all_coins_earned: userRow.all_coins_earned || 0,
      equipped_hat_color: userRow.equipped_hat_color || 0,
      equipped_body_color: userRow.equipped_body_color || 0,
      equipped_banner_color: userRow.equipped_banner_color || 0,
      days_since_joined: displayString,
      sp: userRow.sp || 0,
      kills: userRow.kills || 0,
      damage: userRow.damage || 0,
      wins: userRow.wins || 0,
      
      // country_code: userRow.country_code,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Interner Serverfehler." });
  }
});



const updateHighscores = async () => {
  try {
    const highscores = await userCollection
      .aggregate([
        { 
          $sort: { 
            sp: -1 
          } 
        },
        { 
          $limit: 50 
        },
        { 
          $project: {
            _id: 0,
            username: 1,
            sp: { $ifNull: ["$sp", 0] }
          } 
        }
      ])
      .toArray();

    // Store the updated highscores in a server variable.
    app.set("highscores", highscores);

    console.log("Highscores were successfully updated.");
  } catch (error) {
    console.error("Internal Server Error while updating highscores:", error);
  }
};

updateHighscores();

// Update the highscores every 5 minutes (300000 milliseconds).
setInterval(updateHighscores, 3000000);

app.get("/highscores-coins/:token", checkRequestSize, verifyToken, (req, res) => {
  const highscores = app.get("highscores");

  // Return the highscores in the response.
  res.json(highscores);
});

app.get("/verify-token/:token", checkRequestSize, verifyToken, async (req, res) => {
  const username = req.user.username;

  try {
    const userInformation = await userCollection.findOne(
      { _id: username },
      { projection: { username: 1 } }
    );

    if (!userInformation) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      message: `${username}`,
    });
  } catch (error) {
    console.error("Internal Server Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/verify-gameservertoken/:token", checkRequestSize, verifyToken, async (req, res) => {
  const username = req.user.username;

  try {
    const userInformation = await userCollection.findOne(
      { _id: username },
      {
        projection: {
          equipped_item: 1,
          equipped_item2: 1,
          equipped_color: 1,
          equipped_hat_color: 1,
          equipped_body_color: 1,
        },
      }
    );

    if (!userInformation) {
      return res.status(404).json({ error: "User not found" });
    }

/*    const activity = await gameActivityCollection.findOne(
      { username },
      {
        projection: {
         playing: 1 ,
        },
      }
    );
*/


    
    const {
      equipped_item,
      equipped_item2,
      equipped_color,
      equipped_hat_color,
      equipped_body_color,
    } = userInformation;


    res.json({
      message: `${username}`,
      hat: equipped_item || 0,
      top: equipped_item2 || 0,
      player_color: equipped_color || 0,
      hat_color: equipped_hat_color || 0,
      top_color: equipped_body_color || 0,
     // playing: activity && activity.playing !== null ? activity.playing : 0,
    });

/*  await gameActivityCollection.findOneAndUpdate(
  { username: username }, // Query criteria to find the document for the player
  { $set: { playing: 1 } }, // Update operation to set playing to 1 (or true)
  { upsert: true } // Option to insert a new document if no match is found
);
 */   
  } catch (error) {
    console.error("Internal Server Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/user-count", checkRequestSize, async (req, res) => {
  try {
    const userCount = await db.collection("users").countDocuments();
    res.json({ userCount });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error." });
  }
});

app.get("/total-coins", checkRequestSize, async (req, res) => {
  try {
    const result = await db
      .collection("users")
      .aggregate([
        {
          $group: {
            _id: null,
            totalCoins: { $sum: "$coins" },
          },
        },
      ])
      .toArray();

    const totalCoins = result.length > 0 ? result[0].totalCoins : 0;
    res.json({ totalCoins });
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error." });
  }
});

/*app.post("/increasecoins-lqemfindegiejgkdmdmvu/:username", checkRequestSize, verifychangeserver, async (req, res) => {
  const username = req.params.username;

  try {
    const updateResult = await userCollection.updateOne(
      { username },
      {
        $inc: {
          coins: 2,
          //all_coins_earned: 1,
        },
      },
    );

    const updateResult1 = await battlePassCollection.updateOne(
      { username },
      {
        $inc: {
          season_coins: 1,
        },
      },
      {
        upsert: true,
      },
    );

    if (updateResult.matchedCount === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "Coins increased successfully" });
  } catch (error) {
    console.error("Internal Server Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});





/*app.get("/global-place/:token", checkRequestSize, verifyToken, async (req, res) => {
  const token = req.params.token;
  const username = req.user.username;

  try {

    const userCoinsEarned = req.user.sp || 0;

    const place = await userCollection.countDocuments({
      username: username,
      sp: { $gte: userCoinsEarned },
    });

    res.json({ place });
  } catch (error) {
    console.error("Interner Serverfehler:", error);
    res.status(500).json({ message: "Interner Serverfehler." });
  }
});

*/

// Helper function to respond with an error
function respondWithError(res, errorMessage) {
  res.json({
    error: errorMessage,
  });
}

async function verifyToken(req, res, next) {
  const token = req.params.token;
  const tokenkey = process.env.TOKEN_KEY;

  if (!token) {
    res.status(401).send("Unauthorized");
    return;
  }

  try {
    const decodedToken = jwt.verify(token, tokenkey);

    // Check if the user exists in the database
    const user = await userCollection.findOne(
      { _id: decodedToken.username },
      { projection: { username: 1, token: 1 } }
    );

    if (!user) {
      res.status(401).send("Invalid token");
      return;
    }

    // Attach the user information to the request for later use
    req.user = user.username;
    next();
  } catch (err) {
    res.status(403).send("Invalid token");
  }
}


// Middleware to verify JWT token
/*async function verifyToken(req, res, next) {
  const token = req.params.token;
  const tokenkey = process.env.TOKEN_KEY;

  if (!token) {
    res.status(401).send("Unauthorized");
    return;
  }

  try {
    const decodedToken = jwt.verify(token, tokenkey);

    // Check if the user exists in the database
    const user = await userCollection.findOne(
      { username: decodedToken.username },
      { projection: { username: 1, token: 1 } }
    );

    if (!user) {
      res.status(401).send("Invalid token");
      return;
    }

     if (user.token !== token) {
      res.status(401).send("Invalid token");
      return;
    }

    // Attach the user information to the request for later use
    req.user = user;
    next();
  } catch (err) {
    res.status(403).send("Invalid token");
  }
}

*/

async function checkRequestSize(req, res, next) {
    try {

     if (!sanitizeInputs(req.params)) {
      return res.status(400).send("Unauthorized tq");
    }
    if (!sanitizeInputs(req.query)) {
      return res.status(400).send("Unauthorized oj");
    }
    if (!sanitizeInputs(req.body)) {
      return res.status(400).send("Unauthorized fs");
    }

       req.params1 = mongoSanitize(req.params);
        req.query1 = mongoSanitize(req.query);
        req.body1 = mongoSanitize(req.body);

        // Check if sanitized inputs are valid
        if (!req.params1 || !req.query1 || !req.body1) {
            return res.status(400).send("Unauthorized ss");
        }

        // Check params length

      if (JSON.stringify(req.headers).length > 2500) {
            return res.status(401).send("Unauthorized 1");
        }

      
      for (let param in req.params) {
      if (param === 'token') {
      continue; // Skip checking the 'token' parameter
      }
      if (req.params[param].length > 50) {
      return res.status(401).send("Unauthorized 2");
      }
    }

        // Check body length
        if (req.body && JSON.stringify(req.body).length > 100) {
            return res.status(401).send("Unauthorized 3");
        }

    

        // Check query parameters length
        for (let query in req.query) {
            if (req.query[query].length > 50) {
                return res.status(401).send("Unauthorized 5");
            }
        }

        // Check specific token length in params if it exists
        if (req.params.token && req.params.token.length > 500) {
            return res.status(401).send("Unauthorized 4");
        }

        // Check headers (example: checking the length of a custom header)
        if (req.headers['x-custom-header'] && req.headers['x-custom-header'].length > 500) {
            return res.status(401).send("Unauthorized 6");
        }

        next();
    } catch (error) {
        next(error);
    }
}


app.post("/buy-rarity-box/:token", checkRequestSize, verifyToken, async (req, res) => {
    const token = req.params.token;
    const username = req.user.username;
    const boxprice = 200;

    const session = client.startSession();
    session.startTransaction();

    try {
        // Fetch user details
        const user = await getUserDetails(username, session);

        // Check if user exists
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // Check if user has boxes left
        if (user.boxes < 1) {
            return res.status(404).json({ error: "No boxes left" });
        }

        // Update user's box count
        await updateBoxCount(username, -1, session);

        // Fetch user's owned items
        const ownedItems = user.items || [];

        // Fetch all item ids from the rarity box
        const allItemIds = await getAllItemIds();

        // Find unowned items
        const unownedItems = getUnownedItems(allItemIds, ownedItems);

        // Roll for rarity
        const rarityType = rollForRarity();

        // Determine rewards based on rarity
        const rewards = determineRewards(rarityType, unownedItems, ownedItems);

        // Update user's items and coins
        await updateUserItemsAndCoins(username, rewards, session);

        // Commit transaction
        await session.commitTransaction();

        return res.json(rewards);
    } catch (error) {
        await abortTransaction(session);
        console.error("Transaction aborted:", error);
        return res.status(500).json({ message: "Internal Server Error." });
    } finally {
        endSession(session);
    }
});


function determineRewards(rarityType, unownedItems, ownedItems) {
    let rewards = {};
    if (rarityType < rarity_normal) {
        rewards.coins = [getRandomCoinsReward(), getRandomCoinsReward()];
        rewards.items = [];
        rewards.rarity = "normal";
        rewards.message = `success`;
    } else if (rarityType < rarity_legendary) {
        //rewards.coins = [getRandomCoinsReward(), getRandomCoinsReward()];
       if (unownedItems && unownedItems.length >= 2) {
    rewards.items = getRandomItems(unownedItems, 2).map(item => item.id);
} else {
    // If unownedItems is undefined or has less than 2 items, assign coins instead
    rewards.coins = [getRandomCoinsReward(), getRandomCoinsReward()];
}
        rewards.rarity = "rare";
        rewards.message = `success`;
    } else {
        rewards = handleLegendaryRewards(ownedItems);
    }
    return {
        message: rewards.message,
        rewards: {
            coins: rewards.coins || [],
            items: rewards.items || [],
            rarity: rewards.rarity || "normal",
        },
    };
}

async function updateUserItemsAndCoins(username, rewards, session) {
    if (rewards.rewards.items && rewards.rewards.items.length > 0) {
        await userCollection.updateOne(
            { _id: username },
            { $addToSet: { items: { $each: rewards.rewards.items } } }, // Use rewards.rewards.items directly
            { session }
        );
    }
    if (rewards.rewards.coins) {
        await updateCoins(username, rewards.rewards.coins.reduce((a, b) => a + b, 0), session);
    }
}

async function getUserDetails(username, session) {
  return await userCollection.findOne(
    { _id: username },
    { projection: { _id: 0, username: 1, boxes: 1, items: 1, coins: 1 } },
    { session }
  );
}

async function updateBoxCount(username, count, session) {
  await userCollection.updateOne(
    { _id: username },
    { $inc: { boxes: count } },
    { session }
  );
}

function getUnownedItems(allItemIds, ownedItems) {
  return allItemIds.filter(item => !ownedItems.includes(item.id));
}

function getRandomCoinsReward() {
  return Math.floor(Math.random() * 50) + 1;
}

function getRandomCoinsReward2() {
  return Math.floor(Math.random() * 200) + 130;
}


function rollForRarity() {
  return Math.random();
}



async function updateCoins(username, amount, session) {
  await userCollection.updateOne(
    { _id: username },
    { $inc: { coins: amount } },
    { session }
  );
}

function handleLegendaryRewards(ownedItems) {
  const definedItems = [{ id: "A029" }, { id: "I011" }];
  const definedItemsOwned = definedItems.some(item => ownedItems.includes(item.id));
  if (definedItemsOwned) {
    const rewards = {};
        rewards.coins = [getRandomCoinsReward2(), getRandomCoinsReward2()];
        rewards.items = [];
        rewards.rarity = "legendary";
        rewards.message = `success`;
     return rewards;
  } else {
    return {
      //coins: [getRandomCoinsReward(), getRandomCoinsReward()],
      items: definedItems.map(item => item.id),
      rarity: "legendary",
    };
  }
}

async function abortTransaction(session) {
  if (session && session.inTransaction()) {
    await session.abortTransaction();
  }
}

function endSession(session) {
  if (session) {
    session.endSession();
  }
}

async function getAllItemIds() {
    return await PackItemsCollection.find({}, { _id: 0, id: 1 }).toArray();
}

const battlePassTiers = [
  { tier: 0, price: 0, reward: { coins: 0 } },

  { tier: 1, price: 0, reward: { boxes: 2 } },
  { tier: 2, price: 50, reward: { coins: 150 } },
  { tier: 3, price: 50, reward: { items: ["P009"] } },
  { tier: 4, price: 50, reward: { coins: 200 } },
  { tier: 5, price: 50, reward: { boxes: 5 } },
  { tier: 6, price: 50, reward: { coins: 250 } },
  { tier: 7, price: 50, reward: { items: ["I016"] } },
  { tier: 8, price: 50, reward: { coins: 300 } },
  { tier: 9, price: 50, reward: { coins: 400 } },
  { tier: 10, price: 50, reward: { boxes: 10, items: ["A037", "B028"] } },

  // ... continue defining tiers up to tier 10
];

app.post("/upgrade-battle-pass/:token", checkRequestSize, verifyToken, async (req, res) => {
  const username = req.user.username;

  let session;

  try {
    session = client.startSession();
    session.startTransaction();

    const userRow = await battlePassCollection.findOneAndUpdate(
      { _id:username },
      { $setOnInsert: { season_coins: 0, currentTier: 0 } },
      {
        upsert: true,
        returnDocument: "after",
        projection: { season_coins: 1, currentTier: 1 },
        session,
      },
    );

    if (!userRow) {
      return res.status(401).json({ message: "Invalid request." });
    }

    if (userRow.currentTier > 9) {
      return res.status(401).json({ message: "Max tier reached." });
    }

    // Set currentTier to 1 if it is not defined
    const currentTier = userRow.currentTier || 0;

    // Calculate the next tier
    const nextTier = currentTier + 1;

    // Find the selected tier or set to 1 if not found
    const selectedTier = battlePassTiers.find(
      (passTier) => passTier.tier == nextTier,
    );

    if (!selectedTier) {
      return res.status(401).json({ message: "Selected tier not found." });
    }

    // Check if the user has enough coins to upgrade to the next tier
    if (userRow.season_coins < selectedTier.price) {
      return res
        .status(401)
        .json({ message: "Not enough coins to upgrade to the next tier." });
    }

    // Update the user's coins and set the current tier in the battle pass entry
    const updateResult = await Promise.all([
      battlePassCollection.updateOne(
        { _id:username },
        {
          $inc: { season_coins: -selectedTier.price },
          $set: { currentTier: nextTier },
        },
        { session },
      ),
    ]);

    // Apply the rewards for the upgraded tier
    if (selectedTier.reward.coins) {
      await userCollection.updateOne(
        { _id:username },
        { $inc: { coins: selectedTier.reward.coins } },
        { session },
      );
    }

       if (selectedTier.reward.boxes) {
      await userCollection.updateOne(
        { _id:username },
        { $inc: { boxes: selectedTier.reward.boxes } },
        { session },
      );
    }


    // Add logic to push items to the user's items array
    if (selectedTier.reward.items && selectedTier.reward.items.length > 0) {
      await userCollection.updateOne(
        { _id: username },
        { $push: { items: { $each: selectedTier.reward.items } } },
        { session },
      );
    }

    await session.commitTransaction();

    res.json({
      message: `success ${nextTier}.`,
      //updateResult,
      coinsSpent: selectedTier.price || 0,
      coinsEarned: selectedTier.reward.coins || 0,
      boxesEarned: selectedTier.reward.boxes || 0,
      itemsReceived: selectedTier.reward.items || [],
    });
  } catch (error) {
    await session.abortTransaction();
    console.error("Transaction aborted:", error);
    res.status(500).json({ message: "Internal Server Error." });
  } finally {
    if (session) {
      session.endSession();
    }
  }
});





const loginreward = [
 { reward: { items: ["I015"], coins: 500, boxes: 8 } },
 //  { reward: { items: ["I011"] } },
  // { reward: { coins: 1000, items: ["A032", "B023"] } },
];

app.post("/claim-login-reward/:token", checkRequestSize, verifyToken, async (req, res) => {
  const username = req.user.username;

  let session;

  try {
    session = client.startSession();
    session.startTransaction();

    // Check if the user has already claimed the login reward
   
    const claimedReward = await loginRewardsCollection.findOne({ username });

    if (claimedReward) {
      return res.status(401).json({ message: "Login reward already claimed." });
    }

    // Get the reward from the first item of battlePassTiers
    const reward = loginreward[0].reward;

    // Insert the claimed reward into the login rewards collection
    await loginRewardsCollection.insertOne({
      username,
      claimedAt: new Date(),
    });

    // Process the reward
    let coinsEarned = reward.coins || 0;
    let boxesEarned = reward.boxes || 0;
    let itemsReceived = reward.items || [];

    if (reward.coins) {
      coinsEarned = reward.coins;
      await userCollection.updateOne(
        { _id: username },
        { $inc: { coins: coinsEarned } },
        { session }
      );
    }

    if (reward.boxes) {
      boxesEarned = reward.boxes;
      await userCollection.updateOne(
        { _id: username },
        { $inc: { boxes: boxesEarned } },
        { session }
      );
    }

    if (reward.items && reward.items.length > 0) {
      itemsReceived = reward.items;
      await userCollection.updateOne(
        { _id:username },
        { $push: { items: { $each: itemsReceived } } },
        { session }
      );
    }

    await session.commitTransaction();

    res.json({
      message: "Login reward claimed successfully.",
        coinsEarned: coinsEarned || 0,
        boxesEarned: boxesEarned || 0,
        itemsReceived: itemsReceived || [],
        giftmsg: gift_dev_msg,
      
    });
  } catch (error) {
    await session.abortTransaction();
    console.error("Transaction aborted:", error);
    res.status(500).json({ message: "Internal Server Error." });
  } finally {
    if (session) {
      session.endSession();
    }
  }
});







// Helper function to get random items
function getRandomItems(items, count) {
  const shuffled = items.sort(() => 0.5 - Math.random());
  return shuffled.slice(0, count);
}

// Helper function to check if enough time has passed since the last coin collection
function canCollectCoins(lastCollected) {
  const hoursPassed = (Date.now() - lastCollected) / (1000 * 60 * 60);
  return hoursPassed >= 6;
}

// Helper function to generate a random number within a range
function generateRandomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}



function getCountryCode(userIp) {
  return axios
    .get(`https://ipinfo.io/${userIp}/json`)
    .then((response) => {
      const ipInfo = response.data;
      if (ipInfo && ipInfo.country) {
        return ipInfo.country;
      }
      return "Unknown";
    })
    .catch((error) => {
      console.error("Error while detecting the country:", error);
      return "Unknown";
    });
}

app.use((err, req, res, next) => {
  if (err.timeout) {
    res.status(503).send("Request timed out");
  } else {
    next(err);
  }
});

function readItemsFromFile(filePath) {
  const fileContent = fs.readFileSync(filePath, "utf8");
  // Assuming items are separated by newline
  const itemsArray = fileContent.split("\n");
  return itemsArray;
}

app.get("/compare-items/:username", async (req, res) => {
  const username = req.params.username;

  try {
    const userRow = await userCollection.findOne(
      { _id: username },
      { projection: { items: 1 } },
    );

    if (!userRow) {
      return res.status(401).json({ message: "Invalid request." });
    }

    const userItems = userRow.items;

    // Assuming items.txt is in the same directory as this script
    const filePath = "items.txt";
    const fileItems = readItemsFromFile(filePath);

    // Find items in the file that are not in the user's collection
    const missingItems = fileItems.filter((fileItem) => {
      const itemId = fileItem.split(":")[0]; // Assuming the format is "A023:item:price"
      return !userItems.includes(itemId);
    });

    res.json({ missingItems });
  } catch (error) {
    console.error("Error comparing items:", error);
    res.status(500).json({ message: "Internal Server Error." });
  }
});



/*app.post("/send-friend-request/:token/:friendUsername", checkRequestSize, verifyToken, async (req, res) => {
  const { friendUsername } = req.params;
  const username = req.user.username;

  if (friendUsername.length > 20) {
    return res.status(400).json({ message: "User doesn't exist." });
  }

  if (username === friendUsername) {
    return res.status(400).json({ message: "You can't add yourself." });
  }

  let session;
  try {
    session = client.startSession();
    session.startTransaction();

    const friendExists = await userCollection.findOne(
      { username: friendUsername },
      { projection: { _id: 1 }, session }
    );
    if (!friendExists) {
      await session.abortTransaction();
      return res.status(404).json({ message: "User not found." });
    }

    const userFriendsData = await friendsCollection.findOne(
      { username },
      { projection: { friendRequests: 1, friends: 1 }, session }
    );

    const userFriendRequests = userFriendsData?.friendRequests || [];
    const userFriends = userFriendsData?.friends || [];

    if (userFriendRequests.length >= friendMax) {
      await session.abortTransaction();
      return res.status(400).json({ message: "You have reached the limit of friend requests." });
    }

    const friendFriendsData = await friendsCollection.findOne(
      { username: friendUsername },
      { projection: { friendRequests: 1, friends: 1 }, session }
    );

    const friendFriendRequests = friendFriendsData?.friendRequests || [];
    const friendsdatarequest = friendFriendsData?.friends || [];

     if (friendsdatarequest.length >= friendMax) {
      await session.abortTransaction();
      return res.status(400).json({ message: "The recipient has too many friends." });
    }


    if (friendFriendRequests.length >= friendMax) {
      await session.abortTransaction();
      return res.status(400).json({ message: "The recipient has too many friend requests." });
    }

    if (userFriends.includes(friendUsername)) {
      await session.abortTransaction();
      return res.status(400).json({ message: "Already friends." });
    }

    if (friendFriendRequests.includes(username)) {
      await session.abortTransaction();
      return res.status(400).json({ message: "Friend request already sent." });
    }

    await friendsCollection.updateOne(
      { username: friendUsername },
      { $addToSet: { friendRequests: username } },
      { upsert: true, session }
    );

    await session.commitTransaction();
    eventEmitter.emit('friendRequestSent', { type: "send", from: username, to: friendUsername });
    res.json({ message: "Friend request sent." });
  } catch (error) {
    console.error("Error sending friend request:", error);
    res.status(500).json({ message: "Internal Server Error." });
  } finally {
    if (session) session.endSession();
  }
});

app.post("/accept-friend-request/:token/:friendUsername", checkRequestSize, verifyToken, async (req, res) => {
  const { friendUsername } = req.params;
  const username = req.user.username;

  if (friendUsername.length > 20) {
    return res.status(400).json({ message: "User doesn't exist." });
  }

  let session;
  try {
    session = client.startSession();
    session.startTransaction();

    const userFriendsData = await friendsCollection.findOne(
      { username },
      { projection: { friendRequests: 1, friends: 1 }, session }
    );

    const userFriendRequests = userFriendsData?.friendRequests || [];
    const userFriends = userFriendsData?.friends || [];

    if (!userFriendRequests.includes(friendUsername)) {
      await session.abortTransaction();
      return res.status(400).json({ message: "No friend request found." });
    }

    if (userFriends.length >= friendMax) {
      await session.abortTransaction();
      return res.status(400).json({ message: "You have reached the limit of 10 friends." });
    }

    const friendFriendsData = await friendsCollection.findOne(
      { username: friendUsername },
      { projection: { friends: 1 }, session }
    );

    const friendFriends = friendFriendsData?.friends || [];

    if (friendFriends.length >= friendMax) {
      await session.abortTransaction();
      return res.status(400).json({ message: "The sender has reached the limit of 10 friends." });
    }

    await friendsCollection.updateOne(
      { username },
      {
        $pull: { friendRequests: friendUsername },
        $addToSet: { friends: friendUsername }
      },
      { session }
    );

    await friendsCollection.updateOne(
      { username: friendUsername },
      { $addToSet: { friends: username } },
      { upsert: true, session }
    );

    await session.commitTransaction();
    eventEmitter.emit('friendRequestSent', { type: "accept", from: username, to: friendUsername });
    res.json({ message: "Friend request accepted." });
  } catch (error) {
    console.error("Error accepting friend request:", error);
    res.status(500).json({ message: "Internal Server Error." });
  } finally {
    if (session) session.endSession();
  }
});


*/
app.post("/send-friend-request/:token/:friendUsername", checkRequestSize, verifyToken, async (req, res) => {
  const { friendUsername } = req.params;
  const username = req.user.username;

  if (friendUsername.length > 20) {
    return res.status(400).json({ message: "User doesn't exist." });
  }

  if (username === friendUsername) {
    return res.status(400).json({ message: "You can't add yourself." });
  }

  let session;
  try {
    session = client.startSession();
    session.startTransaction();

      const friendExists = await userCollection.findOne(
      { username: friendUsername },
      { projection: { _id: 1 }, session }
    );



    if (!friendExists) {
      await session.abortTransaction();
      return res.status(404).json({ message: "User not found." });
    }

      const result = await friendsCollection.aggregate([
      {
        $facet: {
          userFriendsData: [
            { $match: { _id: username } },
            { $project: { friendRequests: 1, friends: 1 } }
          ],
          friendFriendsData: [
            { $match: { username: friendUsername } },
            { $project: { friendRequests: 1, friends: 1 } }
          ]
        }
      }
    ], { session }).toArray();

    const [data] = result;
    const userFriendsData = data.userFriendsData[0];
    const friendFriendsData = data.friendFriendsData[0];

    const userFriendRequests = userFriendsData?.friendRequests || [];
    const userFriends = userFriendsData?.friends || [];
    const friendFriendRequests = friendFriendsData?.friendRequests || [];
    const friendsdatarequest = friendFriendsData?.friends || [];

    if (userFriendRequests.length >= friendMax) {
      await session.abortTransaction();
      return res.status(400).json({ message: "You have reached the limit of friend requests." });
    }

    if (friendsdatarequest.length >= friendMax) {
      await session.abortTransaction();
      return res.status(400).json({ message: "The recipient has too many friends." });
    }

    if (friendFriendRequests.length >= friendMax) {
      await session.abortTransaction();
      return res.status(400).json({ message: "The recipient has too many friend requests." });
    }

    if (userFriends.includes(friendUsername)) {
      await session.abortTransaction();
      return res.status(400).json({ message: "Already friends." });
    }

    if (friendFriendRequests.includes(username)) {
      await session.abortTransaction();
      return res.status(400).json({ message: "Friend request already sent." });
    }

    await friendsCollection.updateOne(
      { username: friendUsername },
      { $addToSet: { friendRequests: username } },
      { upsert: true, session }
    );

    await session.commitTransaction();
    eventEmitter.emit('friendRequestSent', { type: "send", from: username, to: friendUsername });
    res.json({ message: "Friend request sent." });
  } catch (error) {
    console.error("Error sending friend request:", error);
    if (session) await session.abortTransaction();
    res.status(500).json({ message: "Internal Server Error." });
  } finally {
    if (session) session.endSession();
  }
});


app.post("/accept-friend-request/:token/:friendUsername", checkRequestSize, verifyToken, async (req, res) => {
  const { friendUsername } = req.params;
  const username = req.user.username;

  if (friendUsername.length > 20) {
    return res.status(400).json({ message: "User doesn't exist." });
  }

  let session;
  try {
    session = client.startSession();
    session.startTransaction();

    const result = await friendsCollection.aggregate([
      {
        $facet: {
          userFriendsData: [
            { $match: { _id: username } },
            { $project: { friendRequests: 1, friends: 1 } }
          ],
          friendFriendsData: [
            { $match: { username: friendUsername } },
            { $project: { friends: 1 } }
          ]
        }
      }
    ], { session }).toArray();

    const [data] = result;
    const userFriendsData = data.userFriendsData[0];
    const friendFriendsData = data.friendFriendsData[0];

    const userFriendRequests = userFriendsData?.friendRequests || [];
    const userFriends = userFriendsData?.friends || [];
    const friendFriends = friendFriendsData?.friends || [];

    if (!userFriendRequests.includes(friendUsername)) {
      await session.abortTransaction();
      return res.status(400).json({ message: "No friend request found." });
    }

    if (userFriends.length >= friendMax) {
      await session.abortTransaction();
      return res.status(400).json({ message: "You have reached the limit of 10 friends." });
    }

    if (friendFriends.length >= friendMax) {
      await session.abortTransaction();
      return res.status(400).json({ message: "The sender has reached the limit of 10 friends." });
    }

    await friendsCollection.bulkWrite([
      {
        updateOne: {
          filter: { _id: username },
          update: {
            $pull: { friendRequests: friendUsername },
            $addToSet: { friends: friendUsername }
          },
          session
        }
      },
      {
        updateOne: {
          filter: { username: friendUsername },
          update: {
            $addToSet: { friends: username }
          },
          upsert: true,
          session
        }
      }
    ]);

    await session.commitTransaction();
    eventEmitter.emit('friendRequestSent', { type: "accept", from: username, to: friendUsername });
    res.json({ message: "Friend request accepted." });
  } catch (error) {
    console.error("Error accepting friend request:", error);
    if (session) await session.abortTransaction();
    res.status(500).json({ message: "Internal Server Error." });
  } finally {
    if (session) session.endSession();
  }
});


app.post("/reject-friend-request/:token/:friendUsername", checkRequestSize, verifyToken, async (req, res) => {
  const { friendUsername } = req.params;
  const username = req.user.username;

  if (friendUsername.length > 20) {
    return res.status(400).json({ message: "User doesn't exist." });
  }

  let session;
  try {
    session = client.startSession();
    session.startTransaction();

    const userFriendsData = await friendsCollection.findOne(
      { _id: username },
      { projection: { friendRequests: 1 }, session }
    );

    const userFriendRequests = userFriendsData?.friendRequests || [];

    if (!userFriendRequests.includes(friendUsername)) {
      await session.abortTransaction();
      return res.status(400).json({ message: "No friend request found." });
    }

    await friendsCollection.updateOne(
      { _id: username },
      { $pull: { friendRequests: friendUsername } },
      { session }
    );

    await session.commitTransaction();
    res.json({ message: "Friend request rejected." });
  } catch (error) {
    console.error("Error rejecting friend request:", error);
    res.status(500).json({ message: "Internal Server Error." });
  } finally {
    if (session) session.endSession();
  }
});

app.delete("/delete-friend/:token/:friendUsername", checkRequestSize, verifyToken, async (req, res) => {
  const { friendUsername } = req.params;
  const username = req.user.username;

  if (friendUsername.length > 20) {
    return res.status(400).json({ message: "User doesn't exist." });
  }

  let session;
  try {
    session = client.startSession();
    session.startTransaction();

    const userFriendsData = await friendsCollection.findOne(
      { _id: username },
      { projection: { friends: 1 }, session }
    );

    const userFriends = userFriendsData?.friends || [];

    if (!userFriends.includes(friendUsername)) {
      await session.abortTransaction();
      return res.status(400).json({ message: "Not friends." });
    }

   await friendsCollection.bulkWrite([
  {
    updateOne: {
      filter: { _id: username },
      update: { $pull: { friends: friendUsername } },
      session
    }
  },
  {
    updateOne: {
      filter: { username: friendUsername },
      update: { $pull: { friends: username } },
      session
    }
  }
]);

    await session.commitTransaction();
    res.json({ message: "Friend deleted." });
  } catch (error) {
    console.error("Error deleting friend:", error);
    res.status(500).json({ message: "Internal Server Error." });
  } finally {
    if (session) session.endSession();
  }
});




/*app.get("/search-users/:token/:text", verifyToken, async (req, res) => {
  const { text } = req.params;

  // Check if the text length is within the required range
  if (text.length < 4 || text.length > 16) {
    return res.status(400).json({ message: "Search text must be between 4 and 16 characters." });
  }

  try {
    const users = await userCollection.find(
      { username: { $regex: text, $options: "i" } },  // Case-insensitive search
      { projection: { username: 1, _id: 0 } }  // Only return the username
    )
    .limit(3)
    .toArray();

    res.json(users);
  } catch (error) {
    console.error("Error searching for users:", error);
    res.status(500).json({ message: "Internal Server Error." });
  }
});

*/

app.get("/search-users/:token/:text", checkRequestSize, verifyToken, async (req, res) => {
  const { text } = req.params;

  // Check if the text length is within the required range
  if (text.length < 4 || text.length > 16) {
    return res.status(400).json({ message: "Search text must be between 4 and 16 characters." });
  }

  try {
    const users = await userCollection.aggregate([
      {
        $match: {
          username: { $regex: text, $options: "i" } // Case-insensitive search
        }
      },
      {
        $project: {
          _id: 0,
          username: 1
        }
      },
      {
        $limit: 3
      }
    ]).toArray();

    res.json(users);
  } catch (error) {
    console.error("Error searching for users:", error);
    res.status(500).json({ message: "Internal Server Error." });
  }
});





app.get("/get-friends/:token", checkRequestSize, verifyToken, async (req, res) => {
  const username = req.user.username;

  try {
    const userFriendsData = await friendsCollection.findOne(
      { _id: username },
      { projection: { friends: 1, friendRequests: 1 } }
    );

    const friends = userFriendsData?.friends || [];
    const friendRequests = userFriendsData?.friendRequests || [];

    res.json({ friends, friendRequests });
  } catch (error) {
    console.error("Error retrieving friends and friend requests collection:", error);
    res.status(500).json({ message: "Internal Server Error." });
  }
});

//eventEmitter.setMaxListeners(50);
app.get('/events/:token', checkRequestSize, verifyToken, async (req, res) => {
  const username = req.user.username;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  res.write('data: connected\n\n');

  let inactivityTimeout;

  const onShopUpdate = (data) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
    resetInactivityTimeout();
  };

  const onFriendRequestSent = (data) => {
    if (data.to === username) {
      const timestamp = new Date().toISOString();
      const eventData = { ...data, timestamp };

      if (data.type === 'send' || data.type === 'accept') {
        eventData.type = data.type;
      }

      res.write(`data: ${JSON.stringify(eventData)}\n\n`);
      resetInactivityTimeout();
    }
  };

  const resetInactivityTimeout = () => {
    if (inactivityTimeout) {
      clearTimeout(inactivityTimeout);
    }
    inactivityTimeout = setTimeout(() => {
      eventEmitter.removeListener('friendRequestSent', onFriendRequestSent);
      eventEmitter.removeListener('shopUpdate', onShopUpdate);
      res.end();
    }, 5 * 60 * 1000); // 5 minutes
  };

  // Set initial inactivity timeout
  resetInactivityTimeout();

  // Register event listeners
  eventEmitter.on('friendRequestSent', onFriendRequestSent);
  eventEmitter.on('shopUpdate', onShopUpdate);

  // Cleanup on client disconnect
  req.on('close', () => {
    clearTimeout(inactivityTimeout);
    eventEmitter.removeListener('friendRequestSent', onFriendRequestSent);
    eventEmitter.removeListener('shopUpdate', onShopUpdate);
    res.end();
  });
});

async function watchItemShop() {
  try {
    await client.connect();

    const documentId = "dailyItems"; // Ensure this matches the actual ID type

    // Create a Change Stream with a pipeline to match changes for the specific document ID
    const pipeline = [
      { $match: { 'fullDocument._id': documentId } }
    ];

    // Watch the collection with the defined pipeline
    const changeStream = shopcollection.watch(pipeline, { fullDocument: 'updateLookup' });

    // Handle changes detected by the Change Stream
    changeStream.on('change', (change) => {
       const timestamp = new Date().toISOString();
         eventEmitter.emit('shopUpdate', { update: "shopupdate", timestamp });
      console.log("Change detected:");
    });

      // Emit the event directly with the change object
  } catch (error) {
    console.error('Error setting up Change Stream:', error);
  }
}

   watchItemShop();





app.use((err, req, res, next) => {
  console.error('An error occurred:', err);

  // Send an appropriate response based on the error
  res.status(500).json({ error: 'Unexpected server error' });

       });




  app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  