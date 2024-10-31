import mongoose from 'mongoose';

// Define the category schema
const categorySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true }, // Name of the category
  description: { type: String }, // Optional description for the category
  createdAt: { type: Date, default: Date.now }, // Creation date
});

// Create and export the Category model
const Category = mongoose.model('Category', categorySchema);
export default Category;