import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({

});

const User = mongoose.Model('User',userSchema);

export default User;