import mongoose from 'mongoose';

// Define the permission schema
const permissionSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true }, // Name of the permission (e.g., 'create_user', 'delete_user')
  description: { type: String }, // Optional description
});

// Create and export the Permission model
const Permission = mongoose.model('Permission', permissionSchema);
export default Permission;