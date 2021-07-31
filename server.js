const express = require("express");
const jwt = require("express-jwt");
const jwtAuthz = require('express-jwt-authz');
const jwksRsa = require("jwks-rsa");
// const authConfig = require("./auth_config.json");
const { join } = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const app = express();

app.use(morgan("dev"));
app.use(helmet());
app.use(express.static(join(__dirname, "public")));

app.use(express.urlencoded({ extended: false }))

// parse application/json
app.use(express.json())


// Create the JWT validation middleware
const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.domain}/.well-known/jwks.json`
  }),

  audience: process.env.audience,
  issuer: `https://${process.env.domain}/`,
  algorithms: ["RS256"],
});



const checkScopes = jwtAuthz(['update:current_user_metadata']);
// Create an endpoint that uses the above middleware to
// protect this route from unauthorized requests
app.put("/api/external/:user_id", checkJwt, checkScopes, async (req, res) => {
  const userId = req.params.user_id;
  // console.log('behold the user id', req.params.user_id);

  var axios = require("axios").default;
  //console.log(req.headers.authorization);

  console.log(req.body);

  var options = {
    method: 'PATCH', url: `https://${process.env.domain}/api/v2/users/${userId}`,
    headers: { authorization: req.headers.authorization, 'content-type': 'application/json' },
    data: {
      user_metadata: { orders: req.body.orders },
    }
  };

  try {
    const response = await axios.request(options)
    // console.log('booyah i should have worked: ', response);
    res.send({
      msg: "Order Received!",
    });
  } catch (error) {
    console.log('Error', error);
  }
});

app.get("/auth_config.json", (req, res) => {
  res.sendFile(join(__dirname, "auth_config.json"));
});

app.get("/*", (_, res) => {
  res.sendFile(join(__dirname, "index.html"));
});

process.on("SIGINT", function () {
  process.exit();
});

// Error handler
app.use(function (err, req, res, next) {
  if (err.name === "UnauthorizedError") {
    return res.status(401).send({ msg: "Invalid token" });
  }

  next(err, req, res);
});

module.exports = app;
