import mongoose from 'mongoose';

// Define the role schema
const roleSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    permissions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Permission' }], // Array of ObjectId references to Permission model
});

// Create the Role model
const Role = mongoose.model('Role', roleSchema);
export default Role;