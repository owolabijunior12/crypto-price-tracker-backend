const CustomError = require('../errors');
const { isTokenValid } = require('../utils');
const { StatusCodes } = require('http-status-codes');
const Token = require('../models/Token');
const { attachCookiesToResponse } = require('../utils');

const authenticateUser = async (req, res, next) => {
  const { refreshToken, accessToken } = req.signedCookies;

  try {
    if (accessToken) {
      const payload = isTokenValid(accessToken);
      req.user = payload.user;
      return next();
    }
    const payload = isTokenValid(refreshToken);

    const existingToken = await Token.findOne({
      user: payload.user.userId,
      refreshToken: payload.refreshToken,
    });

    if (!existingToken || !existingToken?.isValid) {
      throw new CustomError.UnauthenticatedError('Authentication Invalid');
    }

    attachCookiesToResponse({
      res,
      user: payload.user,
      refreshToken: existingToken.refreshToken,
    });

    req.user = payload.user;
    next();
  } catch (error) {
    throw new CustomError.UnauthenticatedError('Authentication Invalid');
  }
};

const authorizePermissions = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      throw new CustomError.UnauthorizedError(
        'Unauthorized to access this route'
      );
    }
    next();
  };
};
const authenticate = (req, res, next) => {
  const password = req.headers['x-api-key'];
  if (password && password === process.env.PASSWORD) {
    res.status(StatusCodes.OK).send('Authorized: You can now access the server');
    next();
  } else {
    res.status(StatusCodes.BAD_REQUEST).send('Unauthorized: Incorrect or missing password');
    throw new CustomError.UnauthenticatedError(' Unauthorized: Incorrect or missing password ');
  }
};


module.exports = {
  authenticateUser,
  authorizePermissions,
  authenticate,
};
