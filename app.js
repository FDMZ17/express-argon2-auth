const express = require('express');
const bodyParser = require('body-parser');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

const JWT_SECRET = 'your_jwt_secret_key';

let users = [];

function generateToken(user) {
    return jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
}

function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'Access denied, no token provided.' });

    jwt.verify(token.split(' ')[1], JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
}

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
        return res.status(400).json({ message: 'Username already exists.' });
    }

    try {
        const hashedPassword = await argon2.hash(password);
        users.push({ username, password: hashedPassword });
        return res.status(201).json({ message: 'User registered successfully.' });
    } catch (error) {
        return res.status(500).json({ message: 'Error registering user.' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(400).json({ message: 'Invalid username or password.' });
    }

    try {
        if (await argon2.verify(user.password, password)) {
            const token = generateToken(user);
            return res.status(200).json({ message: 'Login successful', token });
        } else {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }
    } catch (error) {
        return res.status(500).json({ message: 'Error during login.' });
    }
});

app.get('/protected', authenticateToken, (req, res) => {
    return res.status(200).json({ message: `Welcome ${req.user.username}, you have access to protected data!` });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
