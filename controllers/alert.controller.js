import { triggerAlert } from '../services/alert.service.js';
import supabase from '../config/supabase.js';

export async function trigger(req, res) {
  try {
    // SECURITY FIX: removed the '|| test-user-id' fallback — that was a debug
    // leftover that would silently assign all alerts to a fake user if the JWT
    // middleware ever failed to set req.user. The auth middleware already
    // rejects unauthenticated requests before reaching here, so this is safe.
    const userId = req.user.id;
    const { emailId, score, reason, subject, phone, threatLevel } = req.body;
    const result = await triggerAlert(userId, emailId, score, reason, subject, phone, threatLevel);
    res.json({ success: true, channel: result.channel });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function getHistory(req, res) {
  try {
    const unreadOnly = req.query.unread === 'true';

    let query = supabase
      .from('alerts')
      .select('*')
      .eq('user_id', req.user.id)
      .neq('status', 'cleared')
      .order('created_at', { ascending: false });

    if (unreadOnly) {
      query = query.neq('status', 'resolved');
    }

    // Fetch alerts — exclude cleared ones
    const { data: alertsData, error } = await query;

    if (error) {
      console.log(`[${req.id}] [Alert] getHistory Supabase error:`, JSON.stringify(error));
      throw new Error(error.message);
    }
    if (!alertsData || alertsData.length === 0) return res.json([]);

    // Manual join: fetch emails for alert.email_ids (optional — fails gracefully)
    const emailIds = [...new Set(alertsData.map(a => a.email_id).filter(Boolean))];
    let emailsMap = {};

    if (emailIds.length > 0) {
      // SECURITY FIX: add user_id filter to the emails join.
      // The emailIds list already comes from this user's alerts, so in practice
      // these emails already belong to them — but explicitly filtering by user_id
      // makes the query self-contained and safe against future code changes.
      const { data: emailsData, error: emailsError } = await supabase
        .from('emails')
        .select('id, subject, sender, score, threat_level, scanned_at')
        .in('id', emailIds)
        .eq('user_id', req.user.id); // <-- extra safety: only return this user's emails

      if (emailsError) {
        console.log(`[${req.id}] [Alert] emails join error (non-fatal):`, JSON.stringify(emailsError));
      }

      emailsMap = Object.fromEntries((emailsData || []).map(e => [e.id, e]));
    }

    const normalized = alertsData.map(alert => {
      const email = emailsMap[alert.email_id] || null;
      const channel = alert.type || 'dashboard';
      const isRead = alert.status === 'resolved';

      const title = email?.subject
        ? `High Risk Email: ${email.subject}`
        : `Security Alert via ${channel.charAt(0).toUpperCase() + channel.slice(1)}`;

      const senderDisplay = email?.sender || null;
      const message = senderDisplay
        ? `Suspicious email detected from ${senderDisplay}`
        : `Alert delivered via ${channel}. Status: ${alert.status || 'sent'}`;

      return {
        id: alert.id,
        user_id: alert.user_id,
        threat_id: alert.email_id || null,
        alert_type: channel,
        title,
        message,
        is_sent: alert.status !== 'failed',
        sent_at: alert.created_at,
        is_read: isRead,
        read_at: isRead ? alert.created_at : null,
        created_at: alert.created_at,
      };
    });

    res.json(normalized);
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

// Soft-delete: set status = 'cleared' (avoids Supabase RLS delete restrictions)
export async function deleteAlert(req, res) {
  try {
    const { error } = await supabase
      .from('alerts')
      .update({ status: 'cleared' })
      .eq('id', req.params.id)
      .eq('user_id', req.user.id);

    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function markRead(req, res) {
  try {
    const { id } = req.params;
    const userId = req.user?.id;

    console.log(`[${req.id}] [Alert] Marking as read: ${id} for user: ${userId}`);

    // SECURITY FIX: add .eq('user_id', userId) so a user cannot mark another
    // user's alert as read by guessing or leaking an alert UUID.
    const { data, error } = await supabase
      .from('alerts')
      .update({ status: 'resolved' })
      .eq('id', id)
      .eq('user_id', userId) // <-- only update if this alert belongs to this user
      .select();

    console.log(`[${req.id}] [Alert] Update result - data:`, data, 'error:', error);

    if (error) {
      console.error(`[${req.id}] [Alert] Mark read error:`, error);
      return res.status(500).json({ success: false, error: error.message });
    }

    return res.json({ success: true, updated: data?.length });
  } catch (error) {
    console.error(`[${req.id}] [Alert] markRead exception:`, error);
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function markAllRead(req, res) {
  try {
    const userId = req.user.id;

    const { data, error } = await supabase
      .from('alerts')
      .update({ status: 'resolved' })
      .eq('user_id', userId)
      .neq('status', 'resolved')
      .neq('status', 'cleared')
      .select('id');

    if (error) return res.status(400).json({ success: false, message: error.message });

    res.json({ success: true, count: data?.length ?? 0 });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function resolve(req, res) {
  try {
    // SECURITY FIX: add .eq('user_id', req.user.id) so a user cannot resolve
    // another user's alert by knowing or guessing its UUID.
    const { error } = await supabase
      .from('alerts')
      .update({ status: 'resolved' })
      .eq('id', req.params.id)
      .eq('user_id', req.user.id); // <-- only resolve if it belongs to this user

    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}
