import { Router } from 'express';
import { gmailAuth, gmailCallback } from '../controllers/auth.controller.js';

const router = Router();

router.get('/gmail', gmailAuth);
router.get('/gmail/callback', gmailCallback);

export default router;
