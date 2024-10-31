// import express from 'express';
// import dotenv from 'dotenv';
// import connectDB from './config/db.js';


// dotenv.config();  // This will load the variables from the .env file
// const app = express();
// app.use(express.json());
// app.get('/', (req, res) => {
//     res.send('API is running...');
// });


// // Define the port
// const PORT = process.env.PORT || 5000;

// // Start the server and listen on the specified port
// app.listen(PORT, () => {
//     console.log(`Server running on port ${PORT}`);
// });
// connectDB();
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import connectDB from './config/db.js';
import authRoutes from './routes/authRoutes.js';

dotenv.config();
connectDB();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json()); // Parse JSON bodies

app.use('/api', authRoutes); // Authentication routes

app.get('/', (req, res) => {
    res.send('Server is running');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});