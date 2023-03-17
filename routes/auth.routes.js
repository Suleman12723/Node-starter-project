import { Router } from "express";
const router = Router();
import Controller from "../controllers/authController.js";
import {corsAll,corsWithOptions} from '../utils/cors.js';
import { loginValidators, refreshTokenValidators, signupValidators, validate } from '../middleware/validator.js';



//local auth login
router.post("/login",corsAll, loginValidators(),validate, Controller.Login);

//local auth signup
router.post("/signup",corsAll, signupValidators(), validate, Controller.SignUp);


//Refresh Access Token
router.post('/RefreshAccessToken',corsAll,refreshTokenValidators(),validate, Controller.RefreshAccessToken);




export default router;
