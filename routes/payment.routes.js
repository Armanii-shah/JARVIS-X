import { Router } from 'express';
import Stripe from 'stripe';
import authMiddleware from '../middleware/auth.middleware.js';

const router = Router();

// Initialise Stripe only when the key is present — missing key returns a
// friendly error at runtime rather than crashing the whole server on startup.
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' })
  : null;

function requireStripe(_req, res, next) {
  if (!stripe) {
    console.warn('[Payment] Stripe is not configured — STRIPE_SECRET_KEY is missing.');
    return res.status(503).json({
      success: false,
      message: 'Payment system is not configured yet. Please try again later.',
    });
  }
  next();
}

router.use(authMiddleware);

// ── POST /api/payment/create-subscription ─────────────────────────────────
// Creates a Stripe customer + incomplete subscription and returns the
// PaymentIntent clientSecret so the frontend can confirm payment in-browser.
router.post('/create-subscription', requireStripe, async (req, res) => {
  const { planId } = req.body;
  const { id: userId, email: userEmail } = req.user;

  console.log(`[Payment] create-subscription → user=${userId} email=${userEmail} plan=${planId}`);

  if (!planId) {
    return res.status(400).json({ success: false, message: 'planId is required.' });
  }

  // Demo/test mode — planId is a placeholder (not a real Stripe price ID).
  // Create a one-time PaymentIntent so the checkout UI works for testing.
  const isPlaceholder = planId === 'price_pro_monthly' || planId === 'price_pro_annual';
  if (isPlaceholder) {
    console.log(`[Payment] Demo mode — creating test PaymentIntent instead of subscription`);
    try {
      const amount = planId === 'price_pro_annual' ? 2300 : 2900; // cents
      const paymentIntent = await stripe.paymentIntents.create({
        amount,
        currency: 'usd',
        metadata: { userId, planId, mode: 'demo' },
        description: `JARVIS-X Pro Plan (demo) — ${planId}`,
      });
      console.log(`[Payment] Demo PaymentIntent created: ${paymentIntent.id}`);
      return res.json({
        success: true,
        subscriptionId: null,
        clientSecret: paymentIntent.client_secret,
      });
    } catch (err) {
      console.error('[Payment] Demo PaymentIntent error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  }

  try {
    // Reuse existing customer if one was already created for this user.
    let customerId;
    const existing = await stripe.customers.search({
      query: `metadata['userId']:'${userId}'`,
      limit: 1,
    });

    if (existing.data.length > 0) {
      customerId = existing.data[0].id;
      console.log(`[Payment] Reusing existing Stripe customer ${customerId}`);
    } else {
      const customer = await stripe.customers.create({
        email: userEmail,
        metadata: { userId },
      });
      customerId = customer.id;
      console.log(`[Payment] Created new Stripe customer ${customerId}`);
    }

    const subscription = await stripe.subscriptions.create({
      customer: customerId,
      items: [{ price: planId }],
      payment_behavior: 'default_incomplete',
      payment_settings: { save_default_payment_method: 'on_subscription' },
      expand: ['latest_invoice.payment_intent'],
    });

    const paymentIntent = subscription.latest_invoice?.payment_intent;

    if (!paymentIntent?.client_secret) {
      console.error('[Payment] No client_secret on payment intent:', JSON.stringify(paymentIntent));
      throw new Error('Subscription created but no payment intent was returned.');
    }

    console.log(`[Payment] Subscription ${subscription.id} created — status: ${subscription.status}`);

    return res.json({
      success: true,
      subscriptionId: subscription.id,
      clientSecret: paymentIntent.client_secret,
    });
  } catch (err) {
    console.error('[Payment] create-subscription error:', err.message);
    return res.status(500).json({
      success: false,
      message: err.message ?? 'Failed to create subscription.',
    });
  }
});

// ── POST /api/payment/cancel-subscription ─────────────────────────────────
router.post('/cancel-subscription', requireStripe, async (req, res) => {
  const { subscriptionId } = req.body;
  const { id: userId } = req.user;

  console.log(`[Payment] cancel-subscription → user=${userId} sub=${subscriptionId}`);

  if (!subscriptionId) {
    return res.status(400).json({ success: false, message: 'subscriptionId is required.' });
  }

  try {
    const cancelled = await stripe.subscriptions.cancel(subscriptionId);
    console.log(`[Payment] Subscription ${subscriptionId} cancelled — status: ${cancelled.status}`);
    return res.json({ success: true, status: cancelled.status });
  } catch (err) {
    console.error('[Payment] cancel-subscription error:', err.message);
    return res.status(500).json({
      success: false,
      message: err.message ?? 'Failed to cancel subscription.',
    });
  }
});

// ── POST /api/payment/webhook ──────────────────────────────────────────────
// Raw body required — mount BEFORE express.json() if you add this in production.
// For now this endpoint validates the signature and logs the event type.
router.post('/webhook', requireStripe, async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    if (webhookSecret && sig) {
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } else {
      // Dev fallback — accept unsigned events when secret isn't configured
      event = req.body;
      console.warn('[Payment] Webhook signature not verified (STRIPE_WEBHOOK_SECRET not set).');
    }
  } catch (err) {
    console.error('[Payment] Webhook signature verification failed:', err.message);
    return res.status(400).json({ error: err.message });
  }

  console.log(`[Payment] Webhook event received: ${event.type}`);

  switch (event.type) {
    case 'invoice.payment_succeeded':
      console.log('[Payment] Invoice paid:', event.data.object.id);
      // TODO: update user plan in Supabase to 'pro'
      break;
    case 'invoice.payment_failed':
      console.warn('[Payment] Invoice payment failed:', event.data.object.id);
      // TODO: notify user, downgrade plan
      break;
    case 'customer.subscription.deleted':
      console.log('[Payment] Subscription cancelled:', event.data.object.id);
      // TODO: revert user plan to 'free' in Supabase
      break;
    default:
      console.log(`[Payment] Unhandled event type: ${event.type}`);
  }

  return res.json({ received: true });
});

export default router;
