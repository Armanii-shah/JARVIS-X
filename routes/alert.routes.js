import { Router } from 'express';
import { body } from 'express-validator';
import { trigger, getHistory, markRead, markAllRead, deleteAlert, resolve } from '../controllers/alert.controller.js';
import authMiddleware from '../middleware/auth.middleware.js';
import { validate } from '../middleware/validate.middleware.js';

const router = Router();

router.use(authMiddleware);

router.post('/trigger', [
  body('emailId').notEmpty().withMessage('emailId is required'),
  body('score').isInt({ min: 0, max: 100 }).withMessage('score must be an integer between 0 and 100'),
  body('reason').notEmpty().withMessage('reason is required'),
  body('subject').notEmpty().withMessage('subject is required'),
  body('phone').notEmpty().withMessage('phone is required').isLength({ min: 10 }).withMessage('phone must be at least 10 characters'),
  validate,
], trigger);

router.get('/history', getHistory);
router.patch('/mark-all-read', markAllRead);
router.patch('/:id/read', markRead);
router.delete('/:id', deleteAlert);
router.patch('/resolve/:id', resolve);

export default router;
