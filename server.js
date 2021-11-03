const mongoose = require('mongoose');
const dotenv = require('dotenv');

// catching exception in sync part of code
process.on('uncaughtException', err => {
  console.log('UNCAUGHT EXCEPTION! SHUTTING DOWN...');
  console.log(err.name, err.message);
  process.exit(1);
});
// setting up config file
dotenv.config({ path: './config.env' });
const app = require('./app');

// connecting mongodDB database
const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);
mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true
  })
  .then(con => {
    console.log('DB Connection Successfull');
  });

// setting up the server and initializing
const port = process.env.PORT || 5000;
const server = app.listen(port, () => {
  console.log(`server started at ${port}`);
});
// handling error from unhandled async code
process.on('unhandledRejection', err => {
  console.log(err);
  console.log('Unhandled Rejection Application shutting down...');
  server.close(() => {
    process.exit(1);
  });
});
