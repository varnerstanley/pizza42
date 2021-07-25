const express = require("express");
const jwt = require("express-jwt");
const jwtAuthz = require('express-jwt-authz');
const jwksRsa = require("jwks-rsa");
const authConfig = require("./auth_config.json");
const { join } = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const app = express();

app.use(morgan("dev"));
app.use(helmet());
app.use(express.static(join(__dirname, "public")));

// Create the JWT validation middleware
const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`
  }),

  audience: authConfig.audience,
  issuer: `https://${authConfig.domain}/`,
  algorithms: ["RS256"],
});



const checkScopes = jwtAuthz(['read:orders']);
// Create an endpoint that uses the above middleware to
// protect this route from unauthorized requests
app.get("/api/external", checkJwt, checkScopes, (req, res) => {


  var axios = require("axios").default;
  //console.log(req.headers.authorization);
  var options = {
    method: 'PATCH', url: `https://${authConfig.domain}/api/v2/users/user_id/`,
    headers: { authorization: req.headers.authorization, 'content-type': 'application/json' },
    user_metadata: { pizzaName: "Pepperoni Pizza" }
  };


  axios.request(options).then(function (response) {
    // console.log(response.data);
  }).catch(function (error) {
    console.error(error);
  });

  console.log("I got here.");
  res.send({
    msg: "Access token validated!"
  });
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
