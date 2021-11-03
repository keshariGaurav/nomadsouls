const { promisify } = require('util');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');

const Email = require('../utils/email');

const AppError = require('../utils/appError');

// generating token from secret and id of user
const signToken = id =>
  jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });

// sending res attaching the token
const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    )
  };
  // secure property only works for https
  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
  res.cookie('jwt', token, cookieOptions);
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm
  });
  const url = `${req.protocol}://${req.get('host')}/me`;
  await new Email(newUser, url).sendWelcome();
  createSendToken(newUser, 201, res);
});
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email && !password)
    return next(new AppError('Please provide email id and password', 400));
  const user = await User.findOne({ email }).select('+password');

  // correctPassword is instance method on User object
  if (!user || !(await user.correctPassword(password, user.password)))
    return next(new AppError('Incorrect email or password', 401));
 
  createSendToken(user, 201, res);
});
exports.logout = (req, res) => {
  res.cookie('jwt', 'logged out', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res.status(200).json({ status: 'success' });
};
exports.protect = catchAsync(async (req, res, next) => {
  // cheking user logedIn
  // 1) Fetching Token from header
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }
  if (!token)
    return next(
      new AppError('You are not logged in!. Please login in to get access', 401)
    );

  // 2) Verifying Token and returning payload
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  //3) Checking if user exist
  const freshUser = await User.findById(decoded.id);
  if (!freshUser)
    return next(new AppError('The user does not exist for this token', 401));

  //4) Checking passwordChageTime<tokenTime
  if (freshUser.changedPasswordAfter(decoded.iat))
    return next(
      new AppError('User recently changed password!.Please login again.')
    );

  //5) Attaching user to req object
  req.user = freshUser;
  res.locals.user = freshUser;
  next();
});

// Authorizing User role permission
exports.restrictTo = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return next(
      new AppError('You donot have permission to perform this action.', 403)
    );
  }
  next();
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1) Finding user from email id
  const user = await User.findOne({ email: req.body.email });
  if (!user)
    return next(new AppError('There is no user with these email id', 404));

  //2) Creating reset token from crypto module using instance method
  const resetToken = user.createPasswordResetToken();

  //3) Validator is turning off as passwordConfirm field would be undefined
  await user.save({ validateBeforeSave: false });

  //4) Attaching resetToken to Url
  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/users/resetPassword/${resetToken}`;

  // 5) Sending URL to email
  try {
    await new Email(user, resetURL).sendPasswordReset();
    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!'
    });
  } catch (err) {
    // If error in sending email reset token and expiry time.
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    return next(
      new AppError('There was an error sending the email.Try again later', 500)
    );
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Fetching and encrypting hash token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  //2) Fetching user matching hashToken and token Expiry Date
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });

  if (!user) next(new AppError('Token is invalid or has expired', 400));

  // 3) Setting Up Password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();
  createSendToken(user, 201, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  // 1) Fetching User
  const user = await User.findById(req.user.id).select('+password');

  const { currentPassword, newPassword, confirmPassword } = req.body;
  //2) Validating current Password
  if (!user || !(await user.correctPassword(currentPassword, user.password)))
    return next(
      new AppError('Incorrect Password! Try Again or reset Password', 401)
    );
  // 3) setting up new Password
  user.password = newPassword;
  user.passwordConfirm = confirmPassword;

  await user.save();
  createSendToken(user, 201, res);
});
exports.isLoggedIn = catchAsync(async (req, res, next) => {
  if (req.cookies.jwt) {
    try {
      const decoded = await promisify(jwt.verify)(
        req.cookies.jwt,
        process.env.JWT_SECRET
      );

      const freshUser = await User.findById(decoded.id);
      if (!freshUser) return next();

      //4) Checking passwordChageTime<tokenTime
      if (freshUser.changedPasswordAfter(decoded.iat)) return next();

      //5) Attaching user to req object
      res.locals.user = freshUser;
    } catch (err) {
      return next();
    }
  }
  return next();
});
