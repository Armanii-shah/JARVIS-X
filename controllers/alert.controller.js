import { triggerAlert } from '../services/alert.service.js';
import supabase from '../config/supabase.js';

export async function trigger(req, res) {
  try {
    const userId = req.user?.id || 'test-user-id';
    const { emailId, score, reason, subject, phone } = req.body;
    const result = await triggerAlert(userId, emailId, score, reason, subject, phone);
    res.json({ success: true, channel: result.channel });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function getHistory(req, res) {
  try {
    const { data, error } = await supabase
      .from('alerts')
      .select('*')
      .eq('user_id', req.user.id)
      .order('triggered_at', { ascending: false });

    if (error) throw new Error(error.message);

    res.json(data);
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
