import mongoose from 'mongoose';

// Define the event schema
const eventSchema = new mongoose.Schema({
  title: { type: String, required: true }, // Title of the event
  description: { type: String, required: true }, // Description of the event
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true }, // Reference to the Category model
  date: { type: Date, required: true }, // Date of the event
  location: { type: String, required: true }, // Location of the event
  organizer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Reference to the User model (the organizer)
  ticketsAvailable: {
    vip: { type: Number, required: true, default: 0 },
    general: { type: Number, required: true, default: 0 }, 
  },
  ticketsSold: {
    vip: { type: Number, default: 0 }, // Sold VIP tickets
    general: { type: Number, default: 0 }, // Sold General tickets
  },
  ticketPrice: {
    vip: { type: Number, required: true, default: 0 }, // Price for VIP tickets
    general: { type: Number, required: true, default: 0 }, // Price for General tickets
  },
  
  // Discount settings
  enableEarlyBirdDiscount: { type: Boolean, default: false }, // Enable or disable early bird discount
  enableGroupDiscount: { type: Boolean, default: false }, // Enable or disable group discount

  imageUrl: { type: String }, // URL for the event image (optional)

  // Users who have booked tickets
  bookedUsers: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
    ticketsBooked: Number,
    ticketType: String, // 'VIP' or 'General'
    ticketId: { type: String, required: true }, // Unique ticket ID for each booking
  }],

  createdAt: { type: Date, default: Date.now }, // Creation date
});


// Create and export the Event model
const Event = mongoose.model('Event', eventSchema);
export default Event;
