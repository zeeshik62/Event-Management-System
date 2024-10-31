import mongoose from 'mongoose';

const connectDB = async () => {
    // Create a timeout promise that rejects after 10 seconds
    const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => {
            reject(new Error('MongoDB connection timed out'));
        }, 10000); // 10 seconds timeout
    });

    try {
        // Use Promise.race to race between the MongoDB connection and the timeout
        await Promise.race([mongoose.connect(process.env.MONGO_URI), timeoutPromise]);
        console.log('MongoDB connected');
    } catch (error) {
        console.error('MongoDB connection failed:', error.message, error.stack);
        process.exit(1); // Exit the process with a failure code
    }
};

export default connectDB;