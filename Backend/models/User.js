import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

// Define the user schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: false },
  role: { type: mongoose.Schema.Types.ObjectId, ref: 'Role' },
  permissions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Permission' }], // Direct permissions for the user
  favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Event' }], // Events added to favorites
  createdEvents: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Event' }], // Events created by the user
  bookedEvents: [{
    eventId: { type: mongoose.Schema.Types.ObjectId, ref: 'Event' },
    ticketsBooked: Number,
    ticketType: String, // 'VIP' or 'General'
  }], // Events where tickets have been booked by the user
  otp: { type: String },
  isVerified: { type: Boolean, default: false },
  status: { type: String, enum: ['pending', 'active', 'rejected'], default: 'pending' }, // Organizer status
});

// Password hash middleware
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Create and export the User model
const User = mongoose.model('User', userSchema);
export default User;