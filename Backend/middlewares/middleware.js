import User from '../models/User.js';
import Role from '../models/Role.js';
import jwt from 'jsonwebtoken';

// Middleware to check if user has a specific permission
export const checkPermission = (permissionName) => {
  return async (req, res, next) => {
    const userId = req.user.userId;

    try {
      const user = await User.findById(userId).populate('role').populate('permissions');
      if (!user) return res.status(401).json({ message: 'Unauthorized' });

      // Check role-based permissions
      const role = await Role.findById(user.role).populate('permissions');
      const rolePermissions = role ? role.permissions.map((perm) => perm.name) : [];

      // Check user-specific permissions
      const userPermissions = user.permissions.map((perm) => perm.name);

      // Combine both sets of permissions
      const allPermissions = new Set([...rolePermissions, ...userPermissions]);
      if (allPermissions.has(permissionName)) {
        next();
      } else {
        return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
      }
    } catch (error) {
      return res.status(500).json({ message: 'Server error' });
    }
  };
};

export const authenticateUser = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Assuming the token is sent in 'Bearer <token>' format

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Failed to authenticate token' });
    }
    req.user = { userId: decoded.userId, role: decoded.role }; // Populating req.user
    next();
  });
};
// import jwt from 'jsonwebtoken';
// import dotenv from 'dotenv';

// dotenv.config(); // To use environment variablesnpm i --save-dev @types/jsonwebtoken

// // Middleware to authenticate the user and populate req.user
// export const authenticateToken = (req, res, next) => {
//     const authHeader = req.headers['authorization'];
//     const token = authHeader && authHeader.split(' ')[1]; // Extract token from header

//     if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

//     jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
//         if (err) return res.status(403).json({ message: 'Invalid token.' });

//         req.user = user; // Populate req.user with decoded token data
//         next(); // Proceed to the next middleware or route
//     });
// };

// // Middleware to check if the user is a superadmin
// export const isSuperAdmin = (req, res, next) => {
//      // Log the user object for debugging
//     if (req.user && req.user.role === 'superAdmin') {
//         next(); // Proceed if role is superadmin
//     } else {
//         res.status(403).json({ message: 'Access denied. Only superadmins can perform this action.' });
//         // console.log('User in isSuperAdmin:', req.user.role);
//     }
// };



//6707f9b7d92b0d8143706266 update
//6707f529d92b0d814370624c delete
//6707f51ad92b0d814370624a create

//Roles
//6707faa6d92b0d8143706269 vendor
//6707facbd92b0d814370626b client