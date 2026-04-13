-- Blocked emails table
-- Tracks senders that a user has explicitly blocked.
-- The email_filter_id column stores the Gmail server-side filter ID
-- so it can be deleted if the user ever unblocks the sender.

CREATE TABLE IF NOT EXISTS blocked_emails (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_email    TEXT NOT NULL,
  reason          TEXT,
  email_filter_id TEXT,                -- Gmail filter ID (nullable if filter creation fails)
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (user_id, sender_email)       -- one block rule per sender per user
);

-- Index for the hot query: "is this sender blocked for this user?"
CREATE INDEX IF NOT EXISTS idx_blocked_emails_user_sender
  ON blocked_emails (user_id, sender_email);
