const AppError = require('../utils/appError');

// If id is incorrect
const handleCastErrorDB = err => {
  const message = `Invalid ${err.path}:${err.value}`;
  return new AppError(message, 400);
};
// If unique field has duplicate value
const handleDuplicateFieldsDB = err => {
  const value = err.errmsg.match(/"(.*?[^\\])"/)[0];
  const message = `Duplicate field value ${value}. Please use another value!.`;
  return new AppError(message, 400);
};
// Validation Error
const handleValidationErrorDB = err => {
  const errors = Object.values(err.errors).map(el => el.message);

  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400);
};
// If JWT token is invalid
const handleJWTError = err =>
  new AppError('Invalid Token.Please login again.', 401);
// If token expired
const handleJWTExpiredError = err =>
  new AppError('Your Token has expired.Login again', 401);

// Sending complete Error in dev
const sendErrorDev = (err, req, res) => {
  if (req.originalUrl.startsWith('/api')) {
    res.status(err.statusCode).json({
      status: err.status,
      error: err,
      message: err.message,
      stack: err.stack
    });
  } else {
    res.status(err.statusCode).render('error', {
      title: 'Something went wrong',
      msg: err.message
    });
  }
};
// sending minimum error in production
const sendErrorProd = (err, req, res) => {
  if (req.originalUrl.startsWith('/api')) {
    if (err.isOperational) {
      return res.status(err.statusCode).json({
        status: err.status,
        message: err.message
      });
    }
    console.error('ERROR ', err);
    return res.status(500).json({
      status: 'error',
      message: 'Something went very wrong!'
    });
  }
  if (err.isOperational) {
    return res.status(err.statusCode).render('error', {
      title: err.status,
      msg: err.message
    });
  }
  console.error('ERROR ', err);

  return res.status(500).render('error', {
    title: 'Something went wrong',
    msg: 'Please try again later.'
  });
};
module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  if (process.env.NODE_ENV === 'development') sendErrorDev(err, req, res);
  else if (process.env.NODE_ENV === 'production') {
    if (err.name === 'CastError') err = handleCastErrorDB(err);
    if (err.code === 11000) err = handleDuplicateFieldsDB(err);
    if (err.name === 'ValidationError') err = handleValidationErrorDB(err);
    if (err.name === 'JsonWebTokenError') err = handleJWTError(err);
    if (err.name === 'TokenExpiredError') err = handleJWTExpiredError(err);
    sendErrorProd(err, req, res);
  }
};
