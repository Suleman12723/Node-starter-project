import passport from "passport";
import jwt from "jsonwebtoken";
import JwtStrategyPassport from "passport-jwt";
const JwtStrategy = JwtStrategyPassport.Strategy;
import ExtractJwtPassport from "passport-jwt";
const ExtractJwt = ExtractJwtPassport.ExtractJwt;
import bcrypt from "bcryptjs";
import USER from "../models/user.js";
import UnAuthorized from "../errors/unAuthorized.js";
import dotenv from 'dotenv';
dotenv.config();



//verify password
const verifyPassword = async(password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword)
 
};

//hash Password
const hashPassword = async (saltRounds, password) => {
  let salt = await bcrypt.genSalt(saltRounds);
  let hashed = await bcrypt.hash(password, salt);
  return hashed;
};


// Token generator functions
const accessTokenGenerator = (user) => {
  return jwt.sign(
    {
      _id: user._id,
      email: user.email,
      admin: user.admin,
    },
    process.env.ACCESS_TOKEN_PRIVATE_KEY,
    //TODO: Uncomment this line when deploying to production
    // { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  );
};

const refreshTokenGenerator = (user) => {
  return jwt.sign(
    {
      _id: user._id,
    },
    process.env.REFRESH_TOKEN_PRIVATE_KEY
  );
};

// Extracting Token and verifying it when verifyUser function is called
var opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = process.env.ACCESS_TOKEN_PRIVATE_KEY;

const jwtPassport = passport.use(
  new JwtStrategy(opts, async(payload, done) => {
    try {
      let user = await USER.findById(payload._id);
      if (!user) {
        let err = new NOTFOUND("User Does not exsists");
        return done(err, false);
      } else if (user) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    } catch (err) {
      done(err);
    }
  })
);

// Verify User
const verifyUser = passport.authenticate("jwt", { session: false });

// verfiy Admin
const verifyAdmin = (req, res, next) => {
  if (req.user.admin) {
    next();
  } else {
    let err = new UnAuthorized("You are not Authorized for this request");
    return next(err);
  }
};

// RefreshToken verification
const verifyRefreshToken = async(refreshToken)=>{
    return await jwt.verify(refreshToken,process.env.REFRESH_TOKEN_PRIVATE_KEY)
  
}



export default {
    verifyPassword,
    verifyAdmin,
    verifyRefreshToken,
    verifyUser,
    hashPassword,
    refreshTokenGenerator,
    accessTokenGenerator,


} 