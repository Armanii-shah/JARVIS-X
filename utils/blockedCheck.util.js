import supabase from '../config/supabase.js';

/**
 * Returns true if the given sender email is in the user's block list.
 * @param {string} userId
 * @param {string} senderEmail
 * @returns {Promise<boolean>}
 */
export async function isSenderBlocked(userId, senderEmail) {
  const { data, error } = await supabase
    .from('blocked_emails')
    .select('id')
    .eq('user_id', userId)
    .eq('sender_email', senderEmail)
    .maybeSingle();

  if (error) {
    console.error(`[BlockedCheck] Error checking blocked sender: ${error.message}`);
    return false; // fail open — don't block legitimate mail on DB errors
  }

  return data !== null;
}
