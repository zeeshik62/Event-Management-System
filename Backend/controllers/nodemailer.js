import nodemailer from 'nodemailer';

// Create a Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail', // You can change this to your email service (e.g., 'Outlook', 'Yahoo')
    auth: {
        user: process.env.EMAIL_USER, // Your email address (use environment variable)
        pass: process.env.EMAIL_PASS, // Your email password or app-specific password (use environment variable)
    },
});

// Function to send an email
const sendEmail = async (to, subject, text) => {
    const mailOptions = {
        from: process.env.EMAIL_USER, // sender address
        to, // recipient address
        subject, // Subject line
        text, // plain text body
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Email sent successfully to', to);
    } catch (error) {
        console.error('Error sending email:', error);
        throw error; // Rethrow the error for further handling
    }
};

// Export the sendEmail function
export default sendEmail;