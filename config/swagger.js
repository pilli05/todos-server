const swaggerAutogen = require("swagger-autogen")();

const doc = {
  info: {
    title: "server",
    description: "",
  },
  host: "localhost:5000",
};

const outputFile = "./swagger-output.json";
const routes = ["../index.js"];

swaggerAutogen(outputFile, routes, doc);
