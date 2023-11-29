const express = require("express");
const app = express();
const cors = require("cors");
require("dotenv").config();
var jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 5000;

// middleware
const corsConfig = {
  origin: ["*", "http://localhost:5173", "http://localhost:5174"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
};
app.use(cors(corsConfig));
app.use(express.json());

// =================================================================

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ejkwftr.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    // =================================================================
    // all collections
    const userCollection = client.db("parcelDB").collection("users");
    const bookingCollection = client.db("parcelDB").collection("bookings");
    const paymentCollection = client.db("parcelDB").collection("payments");

    // ---------- Verifiy token & Verify admin API start -----------
    // Verify token middlewares
    const verifyToken = (req, res, next) => {
      console.log("inside verify token", req.headers.authorization);
      if (!req.headers.authorization) {
        return res.status(401).send({ message: "unauthorized access" });
      }
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res
            .status(401)
            .send({ message: "unauthorized access not allowed" });
        }
        req.decoded = decoded;
        next();
      });
    };

    // Use verify admin after verifyToken
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isAdmin = user?.role === "admin";
      if (!isAdmin) {
        return res.status(403).send({ message: "Forbidden access" });
      }
      next();
    };
    // ---------- Verifiy token & Verify admin API end -----------

    // ---------- Bookings API start -----------
    // Find all bookings for show total bookings information
    app.get('/bookings', async(req, res) => {
      const result = await bookingCollection.find().toArray();
      res.send(result);
    });

    // Find all bookings orders for specified users
    app.get("/bookings", async (req, res) => {
      const email = req.query.email;
      const query = { email: email };
      const result = await bookingCollection.find(query).toArray();
      res.send(result);
    });

    // Update 1 Booking by _id
    app.get('/bookings/:id', async(req, res) => {
      const id = req.params.id;
      const query = {_id: new ObjectId(id)};
      const result = await bookingCollection.findOne(query);
      res.send(result);
    });

    // New create a booking order
    app.post("/bookings", async (req, res) => {
      const bookingInfo = req.body;
      const result = await bookingCollection.insertOne(bookingInfo);
      res.send(result);
    });

    // Detete 1 booking order by customers
    app.delete("/bookings/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await bookingCollection.deleteOne(query);
      res.send(result);
    });
    // ---------- Bookings API end -----------

    // ---------- Users API start -----------
    // user related api call / user collection

    // Check user roles
    app.get("/users/:role", async (req, res) => {
      const role = req.params.role;
      const query = {role: role};
      const result = await userCollection.find(query).toArray();
      res.send(result);
    });

    // Find all users
    app.get("/users", async (req, res) => {
      const result = await userCollection.find().toArray();
      res.send(result);
    });

    // Update user profile name and image or etc...
    app.patch('/users/:id', async (req, res) => {
      const info = req.body;
      const id = req.params.id;
      const filter = {_id: new ObjectId(id)};
      const options = { upsert: true };
      const updateDoc = {
        $set: {
          name: info.name,
          image: info.image,
        },
      };
      const result = await userCollection.updateOne(filter, updateDoc, options);
      res.send(result);
    });

    // Get a specific user by email field from database
    app.get("/users/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const result = await userCollection.findOne(query);
      res.send(result);
    });

    // Create a new user
    app.post("/users", async (req, res) => {
      const user = req.body;
      // insert email if user is dosen't existing
      // you can do this many ways (1. email unique 2. upsert 3. simple checking in database)
      const query = { email: user?.email };
      const existingUser = await userCollection.findOne(query);
      if (existingUser) {
        return res.send({ message: "User already exists", insertedId: null });
      }
      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    // Delete user from database and ui
    app.delete("/users/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await userCollection.deleteOne(query);
      res.send(result);
    });

    // Make sure admin by patch
    app.patch(
      "/users/admin/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const filter = { _id: new ObjectId(id) };
        const updatedDoc = {
          $set: {
            role: "admin",
          },
        };
        const result = await userCollection.updateOne(filter, updatedDoc);
        res.send(result);
      }
    );

    // jwt token access codes
    // token create command
    // 1. step: node
    // 2. step: require('crypto').randomBytes(64).toString('hex')
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "3h",
      });
      res.send({ token });
    });

    // Check admin
    app.get("/users/admin/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: "Forbidden access" });
      }

      // check database
      const query = { email: email };
      const user = await userCollection.findOne(query);
      let admin = false;
      if (user) {
        admin = user?.role === "admin";
      }
      res.send({ admin });
    });

    // Check delivery man
    app.get("/users/delivery/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: "Forbidden access" });
      }

      // check database
      const query = { email: email };
      const user = await userCollection.findOne(query);
      let delivery = false;
      if (user) {
        delivery = user?.role === "delivery" ? true : false;
      }
      res.send({ delivery });
    });
    // ---------- Users API end -----------

    // Stripe API codes for payments
    app.post("/create-payment-intent", async (req, res) => {
      const {price} = req.body;
      const amount = parseInt(price * 100);

      // create payment
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount,
        currency: 'usd',
        payment_method_types: ['card']
      });

      res.send({
        clientSecret: paymentIntent.client_secret
      })
    });

    // Confirm payment API
    app.post('/payments', verifyToken, async (req, res) => {
      const payment = req.body;
      const paymentResult = await paymentCollection.insertOne(payment);
      console.log('Payment info', paymentResult);
      res.send(paymentResult);
    });

    // =================================================================

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

// =================================================================

// start the server
app.get("/", (req, res) => {
  res.send("Parcel is sending process sucessfully!");
});

// listen on port
app.listen(port, () => {
  console.log(`Parcel Management App is running now ${port}`);
});
