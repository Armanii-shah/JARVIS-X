import supabase from '../config/supabase.js';

export async function getProfile(req, res) {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.id)
      .single();

    if (error) throw new Error(error.message);

    res.json(data);
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function updateProfile(req, res) {
  try {
    const { phone, plan } = req.body;

    const { error } = await supabase
      .from('users')
      .update({ phone, plan })
      .eq('id', req.user.id);

    if (error) throw new Error(error.message);

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}
