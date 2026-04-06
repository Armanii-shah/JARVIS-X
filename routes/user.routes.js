import { Router } from 'express';
import { body } from 'express-validator';
import { getProfile, updateProfile } from '../controllers/user.controller.js';
import authMiddleware from '../middleware/auth.middleware.js';
import { validate } from '../middleware/validate.middleware.js';

const router = Router();

router.use(authMiddleware);

router.get('/profile', getProfile);
router.patch('/profile', [
  body('phone').optional().isLength({ min: 10, max: 15 }).withMessage('phone must be 10-15 digits'),
  validate,
], updateProfile);

export default router;
