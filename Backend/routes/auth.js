import User from '../models/User.js';
import Role from '../models/Role.js';
import Permission from '../models/Permission.js';
import Event from '../models/Event.js';
import Category from '../models/EventCatagory.js';
import { calculateTicketsAndAddTicketId } from '../utils/ticket.js';
import express from 'express';
import twilio from 'twilio';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import mongoose from 'mongoose';
import passport from 'passport';
import cron from 'node-cron';
import Stripe from 'stripe';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

const router = express.Router();
dotenv.config();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const stripe_publishable_key = Stripe(process.env.Stripe_publishable_key); // Use your Stripe publishable key



// *************** SENDING OTP ***************
// Create a Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const sendConfirmationEmail = async (to, subject, text) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    text,
  };

  await transporter.sendMail(mailOptions);
};

const sendSMS = async (to, message) => {
  const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

  await client.messages.create({
    body: message,
    to, // Text this number
    from: '+17604073230', // Your Twilio number
  });
};

const sendOTP = async (email, otp) => {
  // Your OTP sending logic
  const message = `Your OTP is ${otp}`;
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP Code',
    text: message,
  });
  console.log(`OTP sent to ${email}`);
};


// *************** Social login *************** //


// Define Google OAuth strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/api/auth/google/callback',
  scope: [
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email'
  ]
},
async (accessToken, refreshToken, profile, done) => {
  try {
    console.log('Access Token:', accessToken);
    console.log('Refresh Token:', refreshToken);

    // Check if profile is defined
    if (!profile) {
      return done(new Error('Profile is undefined'), false);
    }

    // Proceed with extracting user information
    const email = profile.emails[0]?.value;
    const name = profile.displayName || 'Unnamed User'; // Default name if undefined

    console.log('Email:', email);
    console.log('Name:', name);

    // Check if the user already exists in the database
    let user = await User.findOne({ email }).populate('role');
    console.log('User:', user);
    if (!user) {
      // User doesn't exist, return necessary data to create a new user
      return done(null, { email, name, newUser: true });
    }

    // User exists, generate a JWT token
    const token = jwt.sign(
      { userId: user._id, role: user.role._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    return done(null, { user, token });
  } catch (error) {
    console.error('Error during Google login callback:', error);
    return done(error, false);
  }
}));


//************  POST request to initiate Google OAuth flow *****************/


// This POST method is used when the user selects a role before Google login
export const handleGoogleAuth = (req, res, next) => {
  const { role } = req.query; // Frontend sends selected role in the body

  if (!role) {
    return res.status(400).json({ message: 'Role is required' });
  }

  // Store the selected role in the session or request object
  req.selectedRole = role;
  console.log('Selected Role:', req.selectedRole);
  next();
};


//****************  Google authentication strategy *******************/


export const handleGoogleAuth_en = passport.authenticate('google',
     { scope: [    
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'], 
      session: false // Disable session support for this route 
      });

export const googleCallback = async (req, res) => {
        console.log('Access Token:', req.user.token);
        console.log('User from Google:', req.user);
        console.log('Query Parameters:', req.query); // Log incoming query parameters      
        const { email, name, newUser } = req.user;     
        try {
          if (newUser) {
            const roleName = req.query.role?.trim(); // Get role from query and trim whitespace
            console.log('Role Name from Query:', roleName); // Log the role name from query
    
            if (!roleName) {
              return res.status(400).json({ message: 'Role is required and must be a string.' });
            }
      
            // Fetch the role by name
            const role = await Role.findOne({ name: roleName });
      
            console.log('Fetched Role:', role); // Log the fetched role object
      
            if (!role) {
              return res.status(400).json({ message: 'Role not found' });
            }
      
            // Create a new user with the found role
            const user = new User({
              name: name || 'Unnamed User',
              email,
              role: role._id, // Assign the ObjectId of the fetched role
              isVerified: true,
            });
      
            await user.save();
      
            const token = jwt.sign(
              { userId: user._id, role: role.name }, // Save userId and role in the JWT token
              process.env.JWT_SECRET,
              { expiresIn: '1h' }
            );
      
            return res.status(201).json({ token, user });
          }
      
          // If the user already exists, send back their token
          const token = req.user.token;
          res.status(200).json({ token, user: req.user.user });
        } catch (error) {
          console.error('Error during Google login callback:', error);
          return res.status(500).json({ message: 'Server error', error: error.message });
        }
      };


// *************** User Registration with tracking of createdBy ***************


export const register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Check if a user with the same email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email!' });
    }

    // Fetch the role from the database to get its name
    const userRole = await Role.findById(role);
    if (!userRole) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    // Set status to 'pending' if the role is 'Organizer'
    let status = 'active'; // Default status for non-organizers
    if (userRole.name === 'Organizers') {  // Check if the role name is 'Organizer'
      status = 'pending';
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const user = new User({ name, email, password, role, otp, status });

    await user.save();
    await sendOTP(email, user.otp);

    // Notify admin about new organizer registration (optional)
    if (status === 'pending') {
      // await notifyAdmin(user);  // Implement this function based on your notification system
      console.log('Wait for approval');
    }

    res.status(201).json({ message: 'User registered, OTP sent to email' });
  } catch (error) {
    res.status(500).json({ message: 'User not registered!', error: error.message });
  }
};


// *************** Verify OTP ***************


export const verifyOTP = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found!' });
    }
    if (user.isVerified) {
      return res.status(400).json({ message: 'User already verified' });
    }

    if (user.otp === otp) {
      user.isVerified = true;
      await user.save();
      return res.status(200).json({ message: 'Email verified successfully' });
    } else {
      return res.status(400).json({ message: 'Invalid OTP!' });
    }
  } catch (error) {
    return res.status(500).json({ message: 'Email not verified!', error: error.message });
  }
};


//*************** Create categories ***************


export const createCategory = async (req, res) => {
  const { name, description } = req.body;

  // Check if name and description are provided and not empty
  if (!name || !description) {
    return res.status(400).json({ message: 'Name and description are required' });
  }

  // Trim the inputs to avoid issues with extra spaces
  const trimmedName = name.trim();
  const trimmedDescription = description.trim();

  if (trimmedName.length === 0 || trimmedDescription.length === 0) {
    return res.status(400).json({ message: 'Name and description cannot be empty' });
  }

  try {
    // Check if the category already exists by name
    const existingCategory = await Category.findOne({ name: trimmedName });
    if (existingCategory) {
      return res.status(400).json({ message: 'Category already exists' });
    }

    // Create a new category if not already existing
    const category = new Category({ name: trimmedName, description: trimmedDescription });
    await category.save();

    // Return success response
    res.status(201).json({ message: 'Category created successfully', category });

  } catch (error) {
    // Handle server error
    res.status(500).json({ message: 'Error creating category', error: error.message });
  }
};


//*************** Get all categories ***************


export const getCategories = async (req, res) => {
  try {
    // Fetch all categories from the database
    const categories = await Category.find();
    
    // Check if no categories exist
    if (categories.length === 0) {
      return res.status(404).json({ message: 'No categories found' });
    }

    // If categories exist, return them with a success message
    res.status(200).json({ message: 'Categories fetched successfully', categories });
    
  } catch (error) {
    // Handle server error
    res.status(500).json({ message: 'Error fetching categories', error: error.message });
  }
};


//*************** Update a category ***************


export const updateCategory = async (req, res) => {
  const { categoryId } = req.params;
  const { name, description } = req.body;

  // Validate categoryId as a valid MongoDB ObjectId
  if (!mongoose.Types.ObjectId.isValid(categoryId)) {
    return res.status(400).json({ message: 'Invalid category ID' });
  }

  // Validate if name and description are provided
  if (!name || !description) {
    return res.status(400).json({ message: 'Name and description are required' });
  }

  // Trim the inputs
  const trimmedName = name.trim();
  const trimmedDescription = description.trim();

  if (trimmedName.length === 0 || trimmedDescription.length === 0) {
    return res.status(400).json({ message: 'Name and description cannot be empty' });
  }

  try {
    // Check if another category with the same name already exists
    const existingCategory = await Category.findOne({ name: trimmedName, _id: { $ne: categoryId } });
    if (existingCategory) {
      return res.status(400).json({ message: 'Another category with the same name already exists' });
    }

    // Update the category
    const category = await Category.findByIdAndUpdate(
      categoryId, 
      { name: trimmedName, description: trimmedDescription }, 
      { new: true }
    );

    // Check if the category exists
    if (!category) {
      return res.status(404).json({ message: 'Category not found' });
    }

    // Return the updated category
    res.status(200).json({ message: 'Category updated successfully', category });

  } catch (error) {
    // Handle server errors
    res.status(500).json({ message: 'Error updating category', error: error.message });
  }
};


//*************** Delete a category ***************


export const deleteCategory = async (req, res) => {
  const { categoryId } = req.params;

  // Validate categoryId as a valid MongoDB ObjectId
  if (!mongoose.Types.ObjectId.isValid(categoryId)) {
    return res.status(400).json({ message: 'Invalid category ID' });
  }

  try {
    // Optionally check if the category is associated with other data (e.g., events)
    const isAssociated = await Event.findOne({ category: categoryId });
    if (isAssociated) {
      return res.status(400).json({ message: 'Cannot delete category associated with events' });
    }

    // Delete the category
    const category = await Category.findByIdAndDelete(categoryId);
    
    // Check if the category exists
    if (!category) {
      return res.status(404).json({ message: 'Category not found' });
    }

    // Return success response
    res.status(200).json({ message: 'Category deleted successfully' });

  } catch (error) {
    // Handle server errors
    res.status(500).json({ message: 'Error deleting category', error: error.message });
  }
};


// *************** Organizer Status peniding/rejected/active ***************


export const approveOrganizer = async (req, res) => {
  try {
    const { userId } = req.params;
    const { status } = req.body;  // 'active' or 'rejected'
    // Find the organizer user and update their status
    const user = await User.findById(userId).populate('role');
    if (!user || user.role.name !== 'Organizers') {
      console.log(user.role.name)
      return res.status(404).json({ message: 'User not found or not an organizer' });
      
    }
    user.status = status;
    await user.save();

    // Notify organizer about the status update
    // await notifyOrganizer(user.email, status);  // Implement notification based on your system

    res.status(200).json({ message: `Organizer ${status === 'active' ? 'approved' : 'rejected'} successfully` });
  } catch (error) {
    res.status(500).json({ message: 'Error approving organizer', error: error.message });
  }
};


// *************** LOGIN ***************


export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find the user by email and populate their role
    const user = await User.findOne({ email }).populate('role');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found!' });
    }
    
    // Check if the user has verified their email
    if (!user.isVerified) {
      return res.status(400).json({ message: 'Email not verified!' });
    }

    // Check if the user is an Organizer and if their status is still pending
    if (user.role.name === 'Organizers') {
      if (user.status === 'pending') {
        return res.status(403).json({ message: 'Your account is pending approval by the admin.' });
      } else if (user.status === 'rejected') {
        return res.status(403).json({ message: 'Your account has been rejected by the admin.' });
      }
    }

    // Compare the provided password with the hashed password in the database
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials!' });
    }

    // Generate a JWT token with the user ID and role
    const token = jwt.sign(
      { userId: user._id, role: user.role.name },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    return res.status(200).json({message: `${user.name} login successfull.`, token  });
  } catch (error) {
    console.error('Error during login:', error);
    return res.status(500).json({ message: 'Server error!', error: error.message });
  }
};


// *************** Add Role ***************


export const addRole = async (req, res) => {
  try {
    const { name, permissions } = req.body;

    // Check if the role already exists
    const existingRole = await Role.findOne({ name });
    if (existingRole) {
      return res.status(400).json({ message: 'Role already exists!' });
    }

    // If the role doesn't exist, proceed to create it
    const role = new Role({ name, permissions });
    await role.save();

    res.status(201).json({ message: 'Role added successfully', role });
  } catch (error) {
    res.status(500).json({ message:'Role not added!',error:error.message });
  }
};


// *************** get All the Roles ***************


export const getRole = async (req, res) => {
  try {
    const roles = await Role.find();
    res.status(200).json(roles);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching roles!', error: error.message });
  }
};


// *************** Update the Role ***************

export const updateRole = async (req,res) => {
  try{
    const {roleId} = req.params;
    const{name, permissions} = req.body;

    const role = await Role.findByIdAndUpdate(
      roleId,
      {name, permissions},
      {new: true, runValidators: true}
    )
    if (!role){
      return res.status(404).json({ message: 'Role not found!' });
    }
    res.status(200).json({message:'Role updated successfully'})
  }
  catch(error) {
    res.status(500).json({ message: 'Error updating role!', error: error.message });
  }
};

// *************** Delete  Role ***************

export const deleteRole =async (req,res) =>{
  try{
    const {roleId} = req.params;
    
    const role = await Role.findByIdAndDelete(roleId)
    if(!role) {
      return res.status(404).json({ message: 'Role not found!' });
    }
    res.status(200).json({ message: 'Role deleted successfully', role });
  }catch (error) {
    res.status(500).json({message:'Error while deleting Role', message: error.message});
  }
}


// *************** Add Permission***************


export const addPermission = async (req, res) => {
  try {
    const { name, description } = req.body;

    //check if permission already exist
    const existingPerm = await Permission.findOne({ name });
    if(existingPerm) {
      res.status(500).json({ message: 'Permission already exists!'})
    }
    const permission = new Permission({ name, description });
    await permission.save();

    res.status(201).json({ message: 'Permission added successfully', permission });
  } catch (error) {
    res.status(500).json({ message: 'Permission not added!' });
  }
};


// *************** Assign Role to User ***************


export const assignRole = async (req, res) => {
  try {
    const { userId, roleId } = req.body;

    // Check if roleId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(roleId)) {
      return res.status(400).json({ message: 'Invalid role ID!' });
    }

    // Check if the role exists in the Role schema
    const roleExists = await Role.findById(roleId);
    if (!roleExists) {
      return res.status(404).json({ message: 'Role not found!' });
    }

    const user = await User.findById(userId);

    // Check if the user exists
    if (!user) {
      return res.status(404).json({ message: 'User not found!' });
    }

    // Check if the role is already assigned
    if (user.role && user.role.equals(roleId)) {
      return res.status(400).json({ message: 'User already has the same role!' });
    }

    // Assign new role
    user.role = roleId; // Use roleId as it is a valid ObjectId string
    await user.save();

    return res.status(200).json({ message: 'Role assigned successfully' });
  } catch (error) {
    return res.status(500).json({ message: 'Role not assigned!', error: error.message });
  }
};


//*************** Assign Permission to Role ***************


export const assignPermissionToRole = async (req, res) => {
  try {
    const { roleId, permissionIds } = req.body;

    const role = await Role.findById(roleId);
    if (!role) return res.status(404).json({ message: 'Role not found' });

    role.permissions = permissionIds;
    await role.save();

    res.status(200).json({ message: 'Permissions assigned to role successfully' });
  } catch (error) {
    res.status(500).json({ message:'Permission not assigned!', error: error.message });
  }
};


//***************/ Assign Permission to User /***************


export const assignPermissionToUser = async (req, res) => {
  try {
    const { userId, permissionIds } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.permissions = permissionIds;
    await user.save();
    res.status(200).json({ message: 'Permissions assigned to user successfully' });
  } catch (error) {
    res.status(500).json({ message:'Permission not assigned to user!', error: error.message });
  }
};


// *************** Create Event ***************


export const addEvents = async (req, res) => {
  try {
    const {
      title,
      description,
      date,
      time,
      location,
      ticketsAvailable, // Default to 0 if not provided
      category,
      imageUrl,
      ticketPrice, // Include ticketPrice in the request body
      enableEarlyBirdDiscount, // Add discount fields
      enableGroupDiscount
    } = req.body;

    // Validate required fields
    if (
      !title ||
      !description ||
      !date ||
      !time ||
      !location ||
      !ticketsAvailable ||
      !category // ticketPrice is not required if event can be free
    ) {
      return res.status(400).json({ message: 'All fields are required!' });
    }
    
    // Combine date and time into a single string
    const eventDateTimeString = `${date} ${time}`; // Example format: "2024-12-15 12:00 PM"
    
    // Create a Date object using the combined string
    const eventDateTime = new Date(eventDateTimeString);

    // Get the current date and time
    const currentDateTime = new Date();
        // Check if an event with the same title already exists for the same organizer
        const organizerId = req.user.userId; // Get the organizer ID from the decoded token
        const existingEvent = await Event.findOne({ title, organizer: organizerId });
    
        if (existingEvent) {
          return res.status(400).json({ message: 'An event with the same title already exists for this organizer!' });
        }
    // Validate if the event date and time is in the future
    if (eventDateTime <= currentDateTime) {
      return res.status(400).json({ message: 'Event date and time must be in the future!' });
    }

    // Validate if the category is provided and exists in the database
    const existingCategory = await Category.findById(category);
    if (!existingCategory) {
      return res.status(400).json({ message: 'Invalid category!' });
    }

    // Check if at least one ticket type is greater than zero
    const { vip = 0, general = 0 } = ticketsAvailable;
    if (vip <= 0 && general <= 0) {
      return res.status(400).json({ message: 'At least one ticket type (VIP or General) must be greater than zero!' });
    }
    // Validate ticket availability and prices
    const { vip: vipPrice, general: generalPrice } = ticketPrice;
        // Check if VIP tickets are available
    if (vip > 0 && general === 0) {
      // If VIP tickets are available and no General tickets are available
      // General ticket price should not be set
      if (generalPrice > 0) {
        return res.status(400).json({ message: 'Please add general tickets as available (greater than zero) before setting the price!' });
      }
    }

    // Check if General tickets are available
    if (general > 0 && vip === 0) {
      // If General tickets are available and no VIP tickets are available
      // VIP ticket price should not be set
      if (vipPrice > 0) {
        return res.status(400).json({ message: 'Please add VIP tickets as available (greater than zero) before setting the price!' });
      }
    }
    // Create the event
    const event = new Event({
      title,
      description,
      date: eventDateTime, // Save the combined event date and time
      location,
      ticketsAvailable, // Use the provided ticketsAvailable object
      ticketsSold: { vip: 0, general: 0 }, // Initialize tickets sold to 0
      ticketPrice, // Use the ticketPrice directly from the request, defaulting to 0 if not provided
      category, // Reference to the Category model
      organizer: organizerId,
      imageUrl: imageUrl || null, // Optional image URL
      enableEarlyBirdDiscount: enableEarlyBirdDiscount || false, // Default to false if not provided
      enableGroupDiscount: enableGroupDiscount || false // Default to false if not provided
    });

    // Save the event
    await event.save();

    // Find the organizer and add the event to their createdEvents array
    await User.findByIdAndUpdate(
      organizerId,
      { $push: { createdEvents: event._id } }, // Add event's ObjectId to createdEvents
      { new: true }
    );

    // Return success response
    res.status(201).json({ message: 'Event created successfully', event });

  } catch (error) {
    console.error('Error creating event:', error);
    res.status(500).json({ message: 'Event not created!', error: error.message });
  }
};


// *************** View Organizer Event ***************


export const getOrganizerEvents = async (req, res) => {
  try {
    // Get the organizer ID from the token (req.user)
    const organizerId = req.user.userId;

    // Find the organizer and populate their created events
    const user = await User.findById(organizerId).populate('createdEvents');

    if (!user) {
      return res.status(404).json({ message: 'Organizer not found!' });
    }

    // Return the list of events created by the organizer
    res.status(200).json({ events: user.createdEvents });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch events!', error: error.message });
  }
};


// *************** View Event (USer Organizer Admin) ***************


export const getEvents = async (req, res) => {
  try {
    const currentDate = new Date(); // Current date and time
    const past30Days = new Date(); // Date 30 days in the past
    past30Days.setDate(currentDate.getDate() - 30);

    const userId = req.user.userId; // Get the logged-in user ID from JWT

    // Find the logged-in user, including their role and created events
    const user = await User.findById(userId).populate('createdEvents').populate('role');

    // Check if the logged-in user is an organizer
    if (user.role.name === 'Organizers') {
      // Fetch the organizer's created events and populate the bookedUsers' userId
      const organizerEvents = await Event.find({ organizer: userId })
        .populate('bookedUsers.userId', 'name email');

      return res.status(200).json({
        message: 'Organizer events and booked users fetched successfully',
        organizerEvents
      });
    }

    // Check if the user is a SuperAdmin
    if (user.role.name === 'SuperAdmin') {
      const events = await Event.find()
        .populate('bookedUsers.userId', 'name email'); // Populate user details of booked users
    
      return res.status(200).json({
        message: 'All events fetched successfully',
        events // Return the populated events directly
      });
    }

    // If the user is not an organizer or SuperAdmin, fetch events from the past 30 days and upcoming events
    if (user.role.name === 'Users') {
      const userEvents = await Event.find({
        $or: [
          { date: { $gte: past30Days, $lte: currentDate } },  // Events in the past 30 days
          { date: { $gt: currentDate } }                      // Upcoming events
        ]
      }).select('-bookedUsers'); // Exclude booked users
    
      res.status(200).json({
        message: 'User events fetched successfully',
        events: userEvents // Return the events as they are
      });
    }
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ message: 'Failed to fetch events!', error: error.message });
  }
};


// *************** Update Organizer Event ***************


export const updateEvent = async (req, res) => {
  try {
    const { eventId } = req.params;
    const organizerId = req.user.userId;

    // Find the event and make sure the logged-in user is the organizer
    const event = await Event.findById(eventId);

    if (!event) {
      return res.status(404).json({ message: 'Event not found!' });
    }

    if (event.organizer.toString() !== organizerId) {
      return res.status(403).json({ message: 'Unauthorized to update this event!' });
    }

    // Prepare the updated data
    const updatedData = {};

    // List of fields to check and update
    const fieldsToUpdate = [
      'title',
      'description',
      'date',
      'location',
      'ticketsAvailable',
      'ticketPrice',
      'enableEarlyBirdDiscount',
      'enableGroupDiscount',
      'imageUrl'
    ];

    // Validate and set values
    for (const field of fieldsToUpdate) {
      if (req.body[field] !== undefined) {
        updatedData[field] = req.body[field]; // Use new value if provided
      } else {
        updatedData[field] = event[field]; // Retain existing value
      }
    }

    // Extract date and time from the request body (if provided)
    const { date, time } = req.body;
    if (date && time) {
      const eventDateTimeString = `${date} ${time}`;
      const eventDateTime = new Date(eventDateTimeString);

      // Validate if the event date and time is in the future
      const currentDateTime = new Date();
      if (eventDateTime <= currentDateTime) {
        return res.status(400).json({ message: 'Event date and time must be in the future!' });
      }

      updatedData.date = eventDateTime; // Update date only if valid
    }

    // Validate if the category is provided and exists in the database
    if (req.body.category) {
      const existingCategory = await Category.findById(req.body.category);
      if (!existingCategory) {
        return res.status(400).json({ message: 'Invalid category!' });
      }
      updatedData.category = req.body.category; // Update category if valid
    }

    // Validate tickets availability and prices
    const { vip = 0, general = 0 } = updatedData.ticketsAvailable || {};
    if (vip <= 0 && general <= 0) {
      return res.status(400).json({ message: 'At least one ticket type (VIP or General) must be greater than zero!' });
    }

    const { vip: vipPrice, general: generalPrice } = updatedData.ticketPrice || {};
    if (vip > 0 && general === 0 && generalPrice > 0) {
      return res.status(400).json({ message: 'Please add general tickets as available before setting the price!' });
    }

    if (general > 0 && vip === 0 && vipPrice > 0) {
      return res.status(400).json({ message: 'Please add VIP tickets as available before setting the price!' });
    }

    // Update the event with validated data
    const updatedEvent = await Event.findByIdAndUpdate(
      eventId,
      { $set: updatedData }, // Update the fields with new or existing values
      { new: true } // Return the updated document
    );

    res.status(200).json({ message: 'Event updated successfully', updatedEvent });
  } catch (error) {
    console.error('Error updating event:', error);
    res.status(500).json({ message: 'Failed to update event!', error: error.message });
  }
};


//****************** Delete Event ********************/


export const deleteEvent = async (req, res) => {
  try {
    const { eventId } = req.params;
    const organizerId = req.user.userId;

    // Find the event and make sure the logged-in user is the organizer
    const event = await Event.findById(eventId);

    if (!event) {
      return res.status(404).json({ message: 'Event not found!' });
    }

    if (event.organizer.toString() !== organizerId) {
      return res.status(403).json({ message: 'Unauthorized to delete this event!' });
    }

    // Delete the event
    await Event.findByIdAndDelete(eventId);

    // Remove the event reference from the organizer's createdEvents array
    await User.findByIdAndUpdate(
      organizerId,
      { $pull: { createdEvents: eventId } }
    );

    res.status(200).json({ message: 'Event deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete event!', error: error.message });
  }
};


//****************** Book Ticket ********************/

const createPaymentMethods = async () => {
  try {
    const paymentMethod = await stripe.paymentMethods.create({
      type: 'us_bank_account',
      us_bank_account: {
        account_holder_type: 'individual', // or 'company'
        account_number: '000123456789', // Use test account numbers
        routing_number: '110000000',
      },
      billing_details: {
        name: 'John Doe',
      },
    });
    return { paymentMethod };
  } catch (error) {
    console.error('Error creating payment method:', error);
    throw new Error('Payment method creation failed'); // This will be caught in the bookTickets function
  }
};

// Update your `bookTickets` function
export const bookTickets = async (req, res) => {
  try {
    const { eventId } = req.params;
    const userId = req.user.userId;
    const { ticketsToBook, ticketType, phoneNumber } = req.body;
    console.log(userId)
    // Validate ticket type and number of tickets
    if (!['vip', 'general'].includes(ticketType) || !ticketsToBook || ticketsToBook <= 0) {
      return res.status(400).json({ message: 'Invalid ticket type or number of tickets!' });
    }

    // Fetch the event and user details
    const event = await Event.findById(eventId).populate('category');
    if (!event) return res.status(404).json({ message: 'Event not found!' });

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found!' });
    const userEmail = user.email;
    // Check available tickets
    if (event.ticketsAvailable[ticketType] < ticketsToBook) {
      return res.status(400).json({ message: `Not enough ${ticketType.toUpperCase()} tickets available!` });
    }

    // Calculate total cost and apply discounts if applicable
    let ticketPrice = event.ticketPrice[ticketType];
    let totalCost = ticketPrice * ticketsToBook;
    let discount = 0;

    const currentDate = new Date();
    const eventDate = new Date(event.date);
    const earlyBirdPeriod = 20 * 24 * 60 * 60 * 1000; // 20 days
    const isEarlyBird = currentDate <= new Date(eventDate.getTime() - earlyBirdPeriod);

    if (isEarlyBird && event.enableEarlyBirdDiscount) discount += 0.10;
    if (ticketsToBook >= 4 && event.enableGroupDiscount) discount += 0.20;
    if (discount > 0) totalCost -= totalCost * discount;

    // Create payment method
    const paymentMethodCreation = await createPaymentMethods();
    const paymentMethodId = paymentMethodCreation.paymentMethod.id;
    // console.log('payment method id', paymentMethodId)

    // Step 1: Create a PaymentIntent
// Step 1: Create a PaymentIntent
const paymentIntent = await stripe.paymentIntents.create({
  amount: totalCost * 100,
  currency: 'usd',
  payment_method: paymentMethodId, // Make sure this is a card payment method
  confirmation_method: 'manual',
  payment_method_types: ['card', 'us_bank_account'], // Include card and any others you need
});

    // Step 2: Confirm the PaymentIntent
    const confirmedPayment = await stripe.paymentIntents.confirm(paymentIntent.id, {
      payment_method: paymentMethodId,
      mandate_data: {
        customer_acceptance: {
          type: 'online',
          online: {
            ip_address: '192.0.2.1', // Dummy IP address
            user_agent: 'Mozilla/5.0', // Dummy User Agent
          },
        },
      },
    });

    // Handle confirmation result
    if (confirmedPayment.error) {
      return res.status(400).json({ message: 'Payment failed!', error: confirmedPayment.error });
    }
    
    if (confirmedPayment.status === 'requires_action') {
    const emailMessage = `Your payment was successful! You booked ${ticketsToBook} ${ticketType} tickets for the event.`;
    await sendConfirmationEmail(userEmail, 'Payment Confirmation', emailMessage);

    const smsMessage = `Payment successful! You've booked ${ticketsToBook} ${ticketType} tickets.`;
    await sendSMS(phoneNumber, smsMessage);
      return res.status(200).json({
        requiresAction: true,
        clientSecret: confirmedPayment.client_secret,
        message: 'Payment requires additional authentication.',
      });
    }

    if (confirmedPayment.status !== 'succeeded') {
      return res.status(400).json({ message: 'Payment not successful!', status: confirmedPayment.status });
    }

    // Proceed with ticket booking
    const ticketId = uuidv4();
    event.ticketsAvailable[ticketType] -= ticketsToBook;
    event.ticketsSold[ticketType] += ticketsToBook;
    event.bookedUsers.push({ userId, ticketsBooked: ticketsToBook, ticketType, ticketId });
    await event.save();

    await User.findByIdAndUpdate(userId, {
      $push: {
        bookedEvents: { eventId, ticketsBooked: ticketsToBook, ticketType, ticketId },
      },
    });

    // Send email and SMS notifications
    if (confirmedPayment.status === 'succeeded') {
    const emailMessage = `Your payment was successful! You booked ${ticketsToBook} ${ticketType} tickets for the event.`;
    await sendConfirmationEmail(userEmail, 'Payment Confirmation', emailMessage);

    const smsMessage = `Payment successful! You've booked ${ticketsToBook} ${ticketType} tickets.`;
    await sendSMS(phoneNumber, smsMessage);
    }
    // Respond with booking and payment confirmation
    res.status(200).json({
      message: 'Tickets booked and payment successful!',
      eventId: event._id,
      ticketsBooked: ticketsToBook,
      userId,
      userEmail,
      ticketId,
      totalCost,
      discountApplied: discount > 0 ? `${(discount * 100).toFixed(0)}%` : 'None',
    });
  } catch (error) {
    console.error('Error during booking or payment:', error);
    res.status(500).json({ message: 'Failed to book tickets or complete payment!', error: error.message });
  }
};


// export const bookTickets = async (req, res) => {
//   try {
//     const { eventId } = req.params;
//     const userId = req.user.userId; // Get the user's ID from the token
//     const userEmail = req.user.email; // Get the user's email from the token
//     const { ticketsToBook, ticketType } = req.body; // Get the number of tickets and ticket type (VIP or General)

//     // Validate ticketType
//     if (!['vip', 'general'].includes(ticketType)) {
//       return res.status(400).json({ message: 'Invalid ticket type!' });
//     }

//     // Validate the number of tickets to book
//     if (!ticketsToBook || ticketsToBook <= 0) {
//       return res.status(400).json({ message: 'Invalid number of tickets to book!' });
//     }

//     // Find the event
//     const event = await Event.findById(eventId).populate('category');
//     if (!event) {
//       return res.status(404).json({ message: 'Event not found!' });
//     }

//     const user = await User.findById(userId);
//     if (!user) {
//       return res.status(404).json({ message: 'User not found!' });
//     }
//     // Check if there are enough tickets available for the chosen ticket type
//     if (event.ticketsAvailable[ticketType] < ticketsToBook) {
//       return res.status(400).json({ message: `Not enough ${ticketType.toUpperCase()} tickets available!` });
//     }

//     // Calculate total price based on the ticket type
//     let ticketPrice = event.ticketPrice[ticketType];
//     let totalCost = ticketPrice * ticketsToBook;

//     // Apply discounts if applicable
//     let discount = 0;

//     // 1. Early Bird Discount: Booking 20 or more days before the event
//     const currentDate = new Date();
//     const eventDate = new Date(event.date);
//     const earlyBirdPeriod = 20 * 24 * 60 * 60 * 1000; // 20 days in milliseconds
//     const isEarlyBird = currentDate <= new Date(eventDate.getTime() - earlyBirdPeriod);

//     if (isEarlyBird && event.enableEarlyBirdDiscount) {
//       discount += 0.10; // 10% early bird discount
//     }

//     // 2. Group Discount: Booking for 4 or more tickets
//     const isGroupBooking = ticketsToBook >= 4;
//     if (isGroupBooking && event.enableGroupDiscount) {
//       discount += 0.20; // 20% group discount
//     }

//     // 3. Apply the discount to the total cost if any
//     if (discount > 0) {
//       const discountAmount = totalCost * discount;
//       totalCost -= discountAmount;
//     }

//     // Generate a unique ticket ID
//     const ticketId = uuidv4(); // Generate a UUID for the booking

//     // Update the event's tickets
//     event.ticketsAvailable[ticketType] -= ticketsToBook; // Decrease available tickets
//     event.ticketsSold[ticketType] += ticketsToBook; // Increase sold tickets

//     // Save the user who booked tickets into the event's bookedUsers array with ticket ID
//     event.bookedUsers.push({
//       userId,
//       ticketsBooked: ticketsToBook,
//       ticketType,
//       ticketId,  // Save the unique ticket ID
//     });

//     // Save the updated event
//     await event.save();

//     // Update the user's booked tickets
//     await User.findByIdAndUpdate(userId, {
//       $push: {
//         bookedEvents: {
//           eventId,
//           ticketsBooked: ticketsToBook,
//           ticketType,
//           ticketId,  // Also save the unique ticket ID in the user's bookings
//         },
//       },
//     });

//     // Respond with success and necessary details
//     res.status(200).json({
//       message: 'Tickets booked successfully!',
//       eventDate: eventDate,
//       eventId: event._id, // Event ID
//       eventTitle: event.title, // Event Title
//       eventDescription: event.description, // Event Description
//       eventCategory: event.category.name, // Event Category
//       ticketsBooked: ticketsToBook, // Total Tickets Booked
//       userId, // User ID
//       userName:user.name, // User Name
//       userEmail, // User Email
//       ticketId, // Unique Ticket ID
//       totalCost, // Total Cost
//       discountApplied: discount > 0 ? (discount * 100).toFixed(0) + '%' : 'None', // Discount Applied as a formatted string
//     });
//   } catch (error) {
//     console.error('Error booking tickets:', error);
//     res.status(500).json({ message: 'Failed to book tickets!', error: error.message });
//   }
// };

//****************** Get Event with Booked Users ********************/


export const getEventWithBookedUsers = async (req, res) => {
  const { eventId } = req.params;

  try {
    // Validate the eventId
    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: 'Invalid event ID' });
    }

    // Find the event by ID and populate the bookedUsers' userId to get user details
    const event = await Event.findById(eventId).populate('bookedUsers.userId', 'name email');

    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }

    // Check if there are any booked users
    if (!event.bookedUsers || event.bookedUsers.length === 0) {
      return res.status(200).json({ message: 'No users have booked tickets for this event yet' });
    }

    res.status(200).json({
      message: 'Event fetched successfully',
      event: {
        title: event.title,
        description: event.description,
        location: event.location,
        date: event.date,
        ticketsAvailable: event.ticketsAvailable,
        ticketsSold: event.ticketsSold,
        bookedUsers: event.bookedUsers, // This contains user data with ticketsBooked and ticketType
      }
    });
  } catch (error) {
    console.error('Error fetching event data:', error);
    res.status(500).json({ message: 'Error fetching event data', error: error.message });
  }
};


//****************** Add event to faourities ********************/


export const addFavoriteEvent = async (req, res) => {
  try {
    const { eventId } = req.params; // Event ID from the URL
    const userId = req.user.userId; // Get the user's ID from the token

    // Check if the user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found!' });
    }

    // Check if the event exists (optional but recommended)
    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: 'Event not found!' });
    }

    // Check if the event is already in favorites
    if (user.favorites.includes(eventId)) {
      return res.status(400).json({ message: 'Event is already in favorites!' });
    }

    // Update the user's favorites array, use $addToSet to avoid duplicates
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $addToSet: { favorites: eventId } }, // Add eventId to favorites
      { new: true } // Return the updated document
    );

    // Check if the update was successful

    res.status(200).json({ message: 'Event added to favorites successfully!' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to add favorite event!', error: error.message });
  }
};


//****************** Delete event From favourities ********************/


export const removeFavoriteEvent = async (req, res) => {
  try {
    const { eventId } = req.params; // Event ID from the URL
    const userId = req.user.userId; // Get the user's ID from the token

    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found!' });
    }

    // Check if the event exists in the user's favorites
    if (!user.favorites.includes(eventId)) {
      return res.status(400).json({ message: 'Event is not in favorites!' });
    }

    // Update the user's favorites array
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $pull: { favorites: eventId } }, // Remove eventId from favorites
      { new: true } // Return the updated document
    );

    // Check if the update was successful
    if (!updatedUser) {
      return res.status(500).json({ message: 'Failed to remove favorite event!' });
    }

    res.status(200).json({ message: 'Event removed from favorites successfully!' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to remove favorite event!', error: error.message });
  }
};


//****************** Get All upcoming event for user ********************/


export const getAllUpcomingEvents = async (req, res) => {
  try {
      const currentDate = new Date(); // This gets the current date and time
      const upcomingEvents = await Event.find({
          date: { $gt: currentDate }, // This checks if the event date and time is greater than the current date and time
      });
      res.status(200).json({ message: 'Upcoming Events!', upcomingEvents }); // Send upcoming events as a response
  } catch (error) {
      res.status(500).json({ message: 'Failed to fetch events!', error: error.message });
  }
};


//****************** Send reminders for upcoming events ********************/

// Function to send reminders for upcoming events
const sendRemindersForUpcomingEvents = async () => {
  const now = new Date();
  const currentTime = now.getTime();

  // Define time intervals in milliseconds
  const oneDayInMillis = 24 * 60 * 60 * 1000; // 1 day
  const twoDaysInMillis = 2 * oneDayInMillis; // 2 days

  // Fetch all events from the database
  const events = await Event.find();

  // Iterate over each event
  for (let event of events) {
    const eventDate = new Date(event.date);
    const eventTime = eventDate.getTime();
    const timeDifference = eventTime - currentTime; // Calculate the time difference in milliseconds

    // Proceed only if the event is in the future
    if (timeDifference > 0) {
      // Check if the event is within the next 2 days
      if (timeDifference <= twoDaysInMillis) {
        // Construct the reminder message
        const reminderMessage = `Reminder: The event "${event.title}" is happening on ${eventDate.toLocaleString()}.`;

        // Send reminder to users
        await sendReminderToUsers(event, reminderMessage);
      }
    } 
  }
};


// Function to send reminder emails to users
const sendReminderToUsers = async (event, message) => {
  // Log the total number of booked users
  console.log(`Total booked users for event "${event.title}": ${event.bookedUsers.length}`);
  console.log('Email successfully sent to');

  // Loop through the users who booked the event
  for (let booking of event.bookedUsers) {
    const userId = booking.userId;
    const user = await User.findById(userId);

    if (user && user.email) {
      try {
        // Send the reminder email using the existing Nodemailer transporter
        await sendReminderEmail(user.email, message);
      } catch (error) {
        console.error(`Failed to send reminder email to ${user.email}:`, error);
      }
    } else {
      console.log(`No valid user found for booking with userId: ${userId}`);
    }
  }
};

// Function to send reminder emails
const sendReminderEmail = async (email, message) => {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Event Reminder',
      text: message,
    });
    console.log(` ${email}`);
  } catch (error) {
    console.error(`Error sending email to ${email}:`, error);
  }
};

// Schedule the reminder job to run at midnight daily
cron.schedule('33 18 * * *', async () => {
  console.log('Running daily reminder task...');
  await sendRemindersForUpcomingEvents();
});




//****************** Search/Browse Event Functionality ********************/

export const searchEvents = async (req, res) => {
  const { keyword, date, category } = req.query;

  const query = {};
  
  // Check if keyword is provided and not empty
  if (keyword && keyword.trim() !== '') {
    query.title = { $regex: keyword.trim(), $options: 'i' }; // Case-insensitive search
  }
  
  // Validate and check date format
  if (date) {
    const parsedDate = new Date(date);
    if (isNaN(parsedDate.getTime())) {
      return res.status(400).json({ message: 'Invalid date format. Please use a valid date.' });
    }
    query.date = { $gte: parsedDate }; // Search for events on or after the specified date
  }
  
  // Check if category is provided and not empty
  if (category && category.trim() !== '') {
    query.category = category.trim(); // Exact match for category
  }

  try {
    const events = await Event.find(query);
    
    if (events.length === 0) {
      return res.status(404).json({ message: 'No matching events found.' });
    }
    
    res.json(events);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching events', error });
  }
};


//****************** Stripe_Payment_Intent ********************/


// Endpoint to create a Payment Method with bank account
export const createPaymentMethod = async (req, res) => {
  try {
    const paymentMethod = await stripe.paymentMethods.create({
      type: 'us_bank_account',
      us_bank_account: {
        account_holder_type: 'individual', // or 'company'
        account_number: '000123456789', // Use test account numbers here
        routing_number: '110000000',
      },
      billing_details: {
        name: 'John Doe',
      },
    });
    res.status(200).json({ paymentMethod });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};




export const payment_intent = async (req, res) => {
  const { amount } = req.body;

  if (!amount) {
    return res.status(400).json({ error: "Missing required param: amount." });
  }

  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: 'usd',
      payment_method_types: ['card', 'us_bank_account'], // Manually specify the allowed payment types
    });
    res.status(200).json({
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const confirm_payment_intent = async (req, res) => {
  const { paymentIntentId, paymentMethodId } = req.body;

  if (!paymentIntentId || !paymentMethodId) {
    return res.status(400).json({ error: "Missing required parameters: paymentIntentId and paymentMethodId." });
  }

  try {
    const confirmedPayment = await stripe.paymentIntents.confirm(paymentIntentId, {
      payment_method: paymentMethodId,
      mandate_data: {
        customer_acceptance: {
          type: 'online',
          online: {
            ip_address: '192.0.2.1', // Example test IP address
            user_agent: 'PostmanRuntime/7.28.4', // Example user agent for Postman
          },
        },
      },
    });
    res.status(200).json(confirmedPayment);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};