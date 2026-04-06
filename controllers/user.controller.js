import supabase from '../config/supabase.js';

const SAFE_PROFILE_FIELDS = 'id, email, phone, plan, created_at';

export async function getProfile(req, res) {
  try {
    const { data, error } = await supabase
      .from('users')
      .select(SAFE_PROFILE_FIELDS)
      .eq('id', req.user.id)
      .single();

    if (error) throw new Error(error.message);
    if (!data) return res.status(404).json({ success: false, message: 'User not found' });

    res.json(data);
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function updateProfile(req, res) {
  try {
    const { phone } = req.body;

    // Only allow phone updates — plan changes must go through billing
    const { error } = await supabase
      .from('users')
      .update({ phone })
      .eq('id', req.user.id);

    if (error) throw new Error(error.message);

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}
