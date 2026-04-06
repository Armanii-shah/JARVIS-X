import { createClient } from '@supabase/supabase-js';

// Backend uses the service role key so it can bypass RLS and insert/read
// on behalf of any user. Never expose this key to the frontend.
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default supabase;
