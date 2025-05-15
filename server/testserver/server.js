import express from 'express';
import bodyParser from 'body-parser';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

const globalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,             // Allow only 10 requests globally per minute
  keyGenerator: () => 'global',  // Make every IP share the same key
  message: 'Too many requests - global lockout for a minute'
});



const app = express();
const PORT = 3000;



// Fake user (hardcoded)
const USERNAME = 'admin';
const PASSWORD = 'password123';

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(morgan('combined')); // log all requests


app.post('/save', globalLimiter, (req, res) => {
  res.send('Data received');
});

// Route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    console.log(`Login attempt: ${username}:${password}`);

    // Simulate login check
    if (username === USERNAME && password === PASSWORD) {
        return res.status(200).json({ message: 'Login successful' });
    } else {
        return res.status(401).json({ message: 'Invalid credentials' });
    }
});

// Default route
app.get('/', (req, res) => {
    res.send('Simple Login Server for Pen Testing Simulation');
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log('Server running on port 3000');
});

