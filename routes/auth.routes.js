import { Router } from 'express';
import { body } from 'express-validator';
import { gmailAuth, gmailCallback, exchangeCode } from '../controllers/auth.controller.js';
import { validate } from '../middleware/validate.middleware.js';

const router = Router();

router.get('/gmail', gmailAuth);
router.get('/gmail/callback', gmailCallback);
router.post('/exchange', [
  body('code').notEmpty().withMessage('code is required'),
  validate,
], exchangeCode);

export default router;
