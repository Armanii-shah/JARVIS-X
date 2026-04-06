import { triggerAlert } from '../services/alert.service.js';
import supabase from '../config/supabase.js';

export async function trigger(req, res) {
  try {
    const userId = req.user?.id || 'test-user-id';
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

    if (error) throw new Error(error.message);
    if (!alertsData || alertsData.length === 0) return res.json([]);

    // Manual join: fetch emails for alert.email_ids
    const emailIds = [...new Set(alertsData.map(a => a.email_id).filter(Boolean))];
    let emailsMap = {};

    if (emailIds.length > 0) {
      const { data: emailsData } = await supabase
        .from('emails')
        .select('id, subject, sender_email, sender_name')
        .in('id', emailIds);

      emailsMap = Object.fromEntries((emailsData || []).map(e => [e.id, e]));
    }

    const normalized = alertsData.map(alert => {
      const email = emailsMap[alert.email_id] || null;
      const channel = alert.type || 'dashboard';
      const isRead = alert.status === 'resolved';

      const title = email?.subject
        ? `High Risk Email: ${email.subject}`
        : `Security Alert via ${channel.charAt(0).toUpperCase() + channel.slice(1)}`;

      const senderDisplay = email?.sender_name || email?.sender_email || null;
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

    console.log('[Alert] Marking as read:', id, 'for user:', userId);

    const { data, error } = await supabase
      .from('alerts')
      .update({ status: 'resolved' })
      .eq('id', id)
      .select();

    console.log('[Alert] Update result - data:', data, 'error:', error);

    if (error) {
      console.error('[Alert] Mark read error:', error);
      return res.status(500).json({ success: false, error: error.message });
    }

    return res.json({ success: true, updated: data?.length });
  } catch (error) {
    console.error('[Alert] markRead exception:', error);
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
    const { error } = await supabase
      .from('alerts')
      .update({ status: 'resolved' })
      .eq('id', req.params.id);

    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}
