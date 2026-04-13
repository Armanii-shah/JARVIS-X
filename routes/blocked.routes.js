import { Router } from 'express';
import authMiddleware from '../middleware/auth.middleware.js';
import {
  blockSender,
  getBlockedSenders,
  unblockSender,
} from '../controllers/blocked.controller.js';

const router = Router();

router.use(authMiddleware);

router.post('/', blockSender);
router.get('/', getBlockedSenders);
router.delete('/:id', unblockSender);

export default router;
