import { Router } from 'express';
import { param } from 'express-validator';
import { scanEmails, getEmailHistory, rescanEmail } from '../controllers/email.controller.js';
import authMiddleware from '../middleware/auth.middleware.js';
import { validate } from '../middleware/validate.middleware.js';

const router = Router();

router.use(authMiddleware);

router.post('/scan', scanEmails);
router.get('/history', getEmailHistory);
router.post('/rescan/:id', [
  param('id').notEmpty().withMessage('id param is required'),
  validate,
], rescanEmail);

export default router;
