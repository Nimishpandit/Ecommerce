const passport = require("passport");

exports.isAuth = (req, res, done) => {
  return passport.authenticate("jwt");
};

exports.sanitizeUser = (user) => {
  return { id: user.id, role: user.role };
};

exports.cookieExtractor = (req) => {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies["jwt"];
  }
  // token =
  // "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1OTgwNzk2OTg3ODA0NzNiOGRhMWMwOSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzA0NzI2MDE4fQ.y1tB66GDr2cRb9AqUudTVCtneLG9rWGfYmJlmn__7O8";
  return token;
};
