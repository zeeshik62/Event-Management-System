import express from 'express';
import { 
  register, 
  login, 
  verifyOTP, 
  addRole, 
  addPermission, 
  assignRole, 
  assignPermissionToRole, 
  assignPermissionToUser,
  addEvents,
  getOrganizerEvents,
  getEvents,
  updateEvent,
  deleteEvent,
  bookTickets,
  addFavoriteEvent,
  removeFavoriteEvent,
  getAllUpcomingEvents,
  handleGoogleAuth,
  handleGoogleAuth_en,
  googleCallback,
  approveOrganizer,
  createCategory,
  getCategories,
  updateCategory,
  deleteCategory,
  searchEvents,
  createPaymentMethod,
  confirm_payment_intent,
  payment_intent,
  getRole,
  updateRole,
  deleteRole
} from './auth.js';
import { checkPermission, authenticateUser } from '../middlewares/middleware.js';
import passport from 'passport';
const router = express.Router();

router.post('/register', register);
router.post('/verify-otp', verifyOTP);
router.post('/login', login);
router.get('/auth/google', handleGoogleAuth, handleGoogleAuth_en);
router.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' ,session: false}), googleCallback);
router.put('/approve-organizer/:userId', authenticateUser, checkPermission('approval_organizer'), approveOrganizer);
//Routes

//**************** Roles ********************/
router.post('/add-role',authenticateUser, checkPermission('add_role'), addRole);
router.get('/get-role', getRole);
router.put('/update-role/:id',authenticateUser, checkPermission('update_role'), updateRole);
router.delete('/delete-role/:id',authenticateUser, checkPermission('delete_role'), deleteRole);
router.post('/assign-role',authenticateUser, checkPermission('assign_role'), assignRole);

//**************** Permissions ********************/
router.post('/add-permission',authenticateUser, checkPermission('add_permission'), addPermission);
router.post('/assign-permission-role',authenticateUser, checkPermission('assign_permission_role'), assignPermissionToRole);
router.post('/assign-permission-user',authenticateUser, checkPermission('assign_permission_user'), assignPermissionToUser);

//**************** Event Category ********************/
router.post('/add-category',authenticateUser, checkPermission('add_category'), createCategory);
router.get('/get-category',authenticateUser, checkPermission('get_category'), getCategories);
router.put('/update-category/:categoryId',authenticateUser, checkPermission('update_category'), updateCategory);
router.delete('/delete-category/:categoryId',authenticateUser, checkPermission('delete_category'), deleteCategory);

//**************** Events ********************/
router.post('/add-events',authenticateUser, checkPermission('add_event'), addEvents);
router.post('/view-events',authenticateUser, checkPermission('view_event'), getOrganizerEvents); 
router.get('/get-events',authenticateUser, checkPermission('view_event'), getEvents);
router.put('/update-events/:eventId',authenticateUser, checkPermission('update_event'), updateEvent);
router.delete('/delete-events/:eventId',authenticateUser, checkPermission('delete_event'), deleteEvent);
router.get('/show-user-events', authenticateUser,checkPermission('get_events_user'), getAllUpcomingEvents);

//**************** Booking Tickets ********************/
router.post('/events/:eventId/book-ticket',authenticateUser, checkPermission('book_ticket'), bookTickets);

//**************** Add Event to Favorites ********************/
router.put('/events/:eventId/favorite', authenticateUser,checkPermission('add_to_favorites'), addFavoriteEvent);
router.delete('/events/:eventId/remove-favorite', authenticateUser,checkPermission('remove_from_favorites'), removeFavoriteEvent);

//**************** Search and Browse Events ********************/
router.get('/events/search', authenticateUser,checkPermission('search_browse'), searchEvents);

//**************** Stripe Payment Gateway********************/
// router.post('/create-payment-intent', authenticateUser,checkPermission('purchase_tickets'), payment_intent);

router.get('/create-payment-method', createPaymentMethod);

router.post('/stripe-payment-intent',authenticateUser,checkPermission('purchase_tickets'), payment_intent);

//**************** Confirm Stripe Payment ********************/
router.post('/confirm-payment-intent',authenticateUser,checkPermission('purchase_tickets'), confirm_payment_intent);



export default router;