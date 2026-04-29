import supabase from '../config/supabase.js';
import { createAuthClient } from '../services/gmail.service.js';
import { google } from 'googleapis';

export async function blockSender(req, res) {
  try {
    const userId = req.user.id;
    const { sender_email, reason } = req.body;

    if (!sender_email) {
      return res.status(400).json({ success: false, message: 'sender_email is required' });
    }

    // Fetch user's encrypted Gmail token
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('gmail_token')
      .eq('id', userId)
      .single();

    if (userError || !user?.gmail_token) {
      return res.status(400).json({ success: false, message: 'Gmail not connected' });
    }

    // Create Gmail API client from stored OAuth token
    const auth = createAuthClient(user.gmail_token);
    const gmail = google.gmail({ version: 'v1', auth });

    // Create a Gmail filter to route emails from this sender to spam
    let emailFilterId = null;
    try {
      console.log('[Blocked] Creating Gmail filter for:', sender_email);
      const filterResponse = await gmail.users.settings.filters.create({
        userId: 'me',
        requestBody: {
          criteria: { from: sender_email },
          action: { addLabelIds: ['SPAM'], removeLabelIds: ['INBOX'] },
        },
      });
      emailFilterId = filterResponse.data.id;
      console.log('[Blocked] Gmail filter response:', JSON.stringify(filterResponse.data));
      console.log(`[Blocked] Gmail filter created: ${emailFilterId} for ${sender_email}`);
    } catch (gmailError) {
      // Log but don't fail — the block will still be recorded in DB
      console.error('[Blocked] Gmail filter FAILED:', gmailError.message, gmailError.response?.data);
    }

    // Insert into blocked_emails (ON CONFLICT DO NOTHING via Supabase upsert)
    const { data: blocked, error: insertError } = await supabase
      .from('blocked_emails')
      .upsert(
        { user_id: userId, sender_email, reason, email_filter_id: emailFilterId },
        { onConflict: 'user_id,sender_email', ignoreDuplicates: false }
      )
      .select()
      .single();

    if (insertError) throw new Error(insertError.message);

    // Move existing inbox emails from this sender to spam
    let movedToSpam = 0;
    try {
      const listRes = await gmail.users.messages.list({
        userId: 'me',
        q: `from:${sender_email} in:inbox`,
        maxResults: 50,
      });
      const msgs = listRes.data.messages || [];
      for (const msg of msgs) {
        try {
          await gmail.users.messages.modify({
            userId: 'me',
            id: msg.id,
            requestBody: { addLabelIds: ['SPAM'], removeLabelIds: ['INBOX'] },
          });
          movedToSpam++;
        } catch (moveErr) {
          console.error(`[Blocked] Failed to move message ${msg.id} to spam: ${moveErr.message}`);
        }
      }
      console.log(`[Blocked] Moved ${movedToSpam} past emails to spam for: ${sender_email}`);
    } catch (spamErr) {
      console.error('[Blocked] Failed to move past emails to spam:', spamErr.message);
    }

    res.status(201).json({
      success: true,
      data: blocked,
      movedToSpam,
      message: `Sender blocked + ${movedToSpam} past email${movedToSpam === 1 ? '' : 's'} moved to spam`,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function getBlockedSenders(req, res) {
  try {
    const userId = req.user.id;

    const { data, error } = await supabase
      .from('blocked_emails')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw new Error(error.message);

    res.json({ success: true, blocked: data });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function unblockSender(req, res) {
  try {
    const userId = req.user.id;
    const { id } = req.params;

    // Fetch the block record (scoped to this user)
    const { data: blockedRecord, error: fetchError } = await supabase
      .from('blocked_emails')
      .select('*')
      .eq('id', id)
      .eq('user_id', userId)
      .single();

    if (fetchError) {
      return res.status(404).json({ success: false, message: 'Block record not found' });
    }

    // Remove the Gmail filter if one was created
    if (blockedRecord.email_filter_id) {
      try {
        const { data: user } = await supabase
          .from('users')
          .select('gmail_token')
          .eq('id', userId)
          .single();

        if (user?.gmail_token) {
          const auth = createAuthClient(user.gmail_token);
          const gmail = google.gmail({ version: 'v1', auth });
          await gmail.users.settings.filters.delete({
            userId: 'me',
            id: blockedRecord.email_filter_id,
          });
          console.log(`[Blocked] Gmail filter deleted: ${blockedRecord.email_filter_id}`);
        }
      } catch (gmailError) {
        // Log but continue with DB deletion
        console.error(`[Blocked] Failed to delete Gmail filter: ${gmailError.message}`);
      }
    }

    // Optionally rescue emails from spam → inbox
    let rescued = 0;
    const shouldRescue = req.query.rescue === 'true';
    if (shouldRescue && blockedRecord.sender_email) {
      try {
        const { data: userForRescue } = await supabase
          .from('users')
          .select('gmail_token')
          .eq('id', userId)
          .single();

        if (userForRescue?.gmail_token) {
          const rescueAuth = createAuthClient(userForRescue.gmail_token);
          const rescueGmail = google.gmail({ version: 'v1', auth: rescueAuth });

          // Search Gmail spam folder for emails from this sender
          const searchRes = await rescueGmail.users.messages.list({
            userId: 'me',
            q: `from:${blockedRecord.sender_email} in:spam`,
            maxResults: 50,
          });

          const msgs = searchRes.data.messages || [];
          for (const msg of msgs) {
            try {
              await rescueGmail.users.messages.modify({
                userId: 'me',
                id: msg.id,
                requestBody: { addLabelIds: ['INBOX'], removeLabelIds: ['SPAM'] },
              });
              rescued++;
            } catch (moveErr) {
              console.error(`[Blocked] Failed to move message ${msg.id} to inbox: ${moveErr.message}`);
            }
          }
          console.log(`[Blocked] Rescued ${rescued} email(s) from spam for ${blockedRecord.sender_email}`);
        }
      } catch (rescueErr) {
        console.error(`[Blocked] Rescue failed: ${rescueErr.message}`);
      }
    }

    // Delete from DB
    const { error: deleteError } = await supabase
      .from('blocked_emails')
      .delete()
      .eq('id', id)
      .eq('user_id', userId);

    if (deleteError) throw new Error(deleteError.message);

    res.json({ success: true, message: 'Sender unblocked', rescued });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}
