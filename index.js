import express from 'express';
import mongoose from 'mongoose';
import User from './models/User.js';
import dotenv from 'dotenv';
import jwt from "jsonwebtoken";
dotenv.config();

const app = express();
const jwtSecret = process.env.JWT_SECRET;
mongoose.connect(process.env.MONGO_URL);

app.get('/test', (req, res) => {
    res.json("test ok");
})

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const createdUser = await User.create({ username, password });
    jwt.sign({ userId: createdUser._id }, jwtSecret, (err, token) => {
        if (err) throw err;
        res.cookie('token', token).status(201).json('ok');
    });
})

app.listen(4000);