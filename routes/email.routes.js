import { Router } from 'express';
import { param } from 'express-validator';
import { scanEmails, getEmailHistory, getSpamEmails, rescueEmail, rescanEmail, retriggerAlert, deleteEmail } from '../controllers/email.controller.js';
import authMiddleware from '../middleware/auth.middleware.js';
import { validate } from '../middleware/validate.middleware.js';

const router = Router();

router.use(authMiddleware);

router.post('/scan', scanEmails);
router.get('/history', getEmailHistory);
router.get('/spam', getSpamEmails);
router.post('/rescue/:gmailMessageId', [
  param('gmailMessageId').notEmpty().withMessage('gmailMessageId param is required'),
  validate,
], rescueEmail);
router.post('/rescan/:id', [
  param('id').notEmpty().withMessage('id param is required'),
  validate,
], rescanEmail);

router.post('/retrigger-alert/:id', [
  param('id').notEmpty().withMessage('id param is required'),
  validate,
], retriggerAlert);

router.delete('/:id', [
  param('id').notEmpty().withMessage('id param is required'),
  validate,
], deleteEmail);

export default router;
