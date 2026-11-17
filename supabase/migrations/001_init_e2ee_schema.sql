-- supabase/migrations/001_init_e2ee_schema.sql
-- Idempotent initial schema for a zero-knowledge, end-to-end encrypted
-- real-time messenger (React 19 + Vite + Supabase Auth/Realtime/Storage).

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- profiles
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
  username TEXT UNIQUE,
  display_name TEXT,
  avatar_url TEXT,
  bio TEXT,
  last_seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- user_keys (E2EE per-device keys)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.user_keys (
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  ecdh_public_jwk JSONB NOT NULL,
  ecdsa_public_jwk JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, device_id)
);

-- ---------------------------------------------------------------------------
-- user_privacy_settings
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.user_privacy_settings (
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
  last_seen_visibility TEXT NOT NULL DEFAULT 'contacts',
  avatar_visibility TEXT NOT NULL DEFAULT 'contacts',
  bio_visibility TEXT NOT NULL DEFAULT 'contacts',
  read_receipts BOOLEAN NOT NULL DEFAULT true,
  typing_indicators BOOLEAN NOT NULL DEFAULT true,
  group_add_policy TEXT NOT NULL DEFAULT 'contacts',
  default_disappearing_seconds INT,
  hide_notification_content BOOLEAN NOT NULL DEFAULT false,
  blur_on_unfocus BOOLEAN NOT NULL DEFAULT false,
  disable_link_previews BOOLEAN NOT NULL DEFAULT false
);

-- ---------------------------------------------------------------------------
-- contacts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.contacts (
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  contact_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, contact_id),
  CONSTRAINT contacts_not_self CHECK (user_id <> contact_id)
);

-- ---------------------------------------------------------------------------
-- blocked_users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.blocked_users (
  blocker_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  blocked_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (blocker_id, blocked_id),
  CONSTRAINT blocked_not_self CHECK (blocker_id <> blocked_id)
);

-- ---------------------------------------------------------------------------
-- conversations
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.conversations (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  type TEXT NOT NULL DEFAULT 'direct' CHECK (type IN ('direct', 'group')),
  name TEXT,
  created_by UUID NOT NULL REFERENCES auth.users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- conversation_members
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.conversation_members (
  conversation_id UUID NOT NULL REFERENCES public.conversations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
  disappearing_seconds INT,
  is_locked BOOLEAN NOT NULL DEFAULT false,
  muted_until TIMESTAMPTZ,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (conversation_id, user_id)
);

-- ---------------------------------------------------------------------------
-- messages
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.messages (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  conversation_id UUID NOT NULL REFERENCES public.conversations(id) ON DELETE CASCADE,
  sender_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  ciphertext TEXT NOT NULL,
  iv TEXT NOT NULL,
  signature TEXT,
  message_type TEXT NOT NULL DEFAULT 'text',
  is_view_once BOOLEAN NOT NULL DEFAULT false,
  viewed_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  deleted_for_everyone BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- message_receipts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.message_receipts (
  message_id UUID NOT NULL REFERENCES public.messages(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  delivered_at TIMESTAMPTZ,
  read_at TIMESTAMPTZ,
  PRIMARY KEY (message_id, user_id)
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_messages_conversation_created
  ON public.messages(conversation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_sender
  ON public.messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_message_receipts_message
  ON public.message_receipts(message_id);
CREATE INDEX IF NOT EXISTS idx_conversation_members_user
  ON public.conversation_members(user_id);
CREATE INDEX IF NOT EXISTS idx_contacts_user
  ON public.contacts(user_id);
CREATE INDEX IF NOT EXISTS idx_blocked_users_blocker
  ON public.blocked_users(blocker_id);
CREATE INDEX IF NOT EXISTS idx_blocked_users_blocked
  ON public.blocked_users(blocked_id);

-- ---------------------------------------------------------------------------
-- Trigger: auto-create default profiles + user_privacy_settings on new user
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (
    id, username, display_name, avatar_url, bio, last_seen_at, created_at
  )
  VALUES (
    NEW.id,
    (NEW.raw_user_meta_data ->> 'username')::text,
    (NEW.raw_user_meta_data ->> 'full_name')::text,
    (NEW.raw_user_meta_data ->> 'avatar_url')::text,
    NULL,
    NULL,
    now()
  )
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO public.user_privacy_settings (
    user_id, last_seen_visibility, avatar_visibility, bio_visibility,
    read_receipts, typing_indicators, group_add_policy,
    default_disappearing_seconds, hide_notification_content,
    blur_on_unfocus, disable_link_previews
  )
  VALUES (
    NEW.id,
    'contacts', 'contacts', 'contacts',
    true, true, 'contacts',
    NULL, false, false, false
  )
  ON CONFLICT (user_id) DO NOTHING;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

-- ---------------------------------------------------------------------------
-- Revoke default grants (anon and authenticated) then grant narrowly
-- ---------------------------------------------------------------------------
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM anon, authenticated;
REVOKE ALL ON SCHEMA public FROM anon, authenticated;

GRANT USAGE ON SCHEMA public TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO authenticated;

-- ---------------------------------------------------------------------------
-- Row Level Security (enabled on every table)
-- ---------------------------------------------------------------------------
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_privacy_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.blocked_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.conversation_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.message_receipts ENABLE ROW LEVEL SECURITY;

-- Helper: current user is a member of a conversation
CREATE OR REPLACE FUNCTION public.is_conversation_member(conversation_id UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.conversation_members
    WHERE conversation_id = is_conversation_member.conversation_id
      AND user_id = auth.uid()
  );
$$ LANGUAGE sql STABLE;

-- Helper: a blocking relationship exists between two users
CREATE OR REPLACE FUNCTION public.is_blocked_between(user_a UUID, user_b UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.blocked_users
    WHERE (blocker_id = user_a AND blocked_id = user_b)
       OR (blocker_id = user_b AND blocked_id = user_a)
  );
$$ LANGUAGE sql STABLE;

-- ---------------------------------------------------------------------------
-- profiles policies
-- ---------------------------------------------------------------------------
CREATE POLICY "Users can view own profile"
ON public.profiles FOR SELECT TO authenticated
USING (auth.uid() = id);

CREATE POLICY "Users can view contact profiles"
ON public.profiles FOR SELECT TO authenticated
USING (
  auth.uid() <> id
  AND EXISTS (
    SELECT 1 FROM public.contacts
    WHERE contacts.user_id = auth.uid() AND contacts.contact_id = profiles.id
  )
  AND NOT public.is_blocked_between(auth.uid(), profiles.id)
);

CREATE POLICY "Users can view conversation member profiles"
ON public.profiles FOR SELECT TO authenticated
USING (
  auth.uid() <> id
  AND EXISTS (
    SELECT 1 FROM public.conversation_members cm
    JOIN public.conversation_members cm2
      ON cm2.conversation_id = cm.conversation_id
     AND cm2.user_id = auth.uid()
    WHERE cm.user_id = profiles.id
  )
  AND NOT public.is_blocked_between(auth.uid(), profiles.id)
);

CREATE POLICY "Users can update own profile"
ON public.profiles FOR UPDATE TO authenticated
USING (auth.uid() = id)
WITH CHECK (auth.uid() = id);

-- ---------------------------------------------------------------------------
-- user_keys policies
-- ---------------------------------------------------------------------------
CREATE POLICY "Users can view own keys"
ON public.user_keys FOR SELECT TO authenticated
USING (auth.uid() = user_id);

CREATE POLICY "Users can view conversation members' keys"
ON public.user_keys FOR SELECT TO authenticated
USING (
  auth.uid() <> user_id
  AND EXISTS (
    SELECT 1 FROM public.conversation_members cm
    JOIN public.conversation_members cm2
      ON cm2.conversation_id = cm.conversation_id
     AND cm2.user_id = auth.uid()
    WHERE cm.user_id = user_keys.user_id
  )
  AND NOT public.is_blocked_between(auth.uid(), user_keys.user_id)
);

CREATE POLICY "Users can insert own keys"
ON public.user_keys FOR INSERT TO authenticated
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own keys"
ON public.user_keys FOR UPDATE TO authenticated
USING (auth.uid() = user_id)
WITH CHECK (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- user_privacy_settings policies
-- ---------------------------------------------------------------------------
CREATE POLICY "Users can view own privacy settings"
ON public.user_privacy_settings FOR SELECT TO authenticated
USING (auth.uid() = user_id);

CREATE POLICY "Users can view conversation members' privacy settings"
ON public.user_privacy_settings FOR SELECT TO authenticated
USING (
  auth.uid() <> user_id
  AND EXISTS (
    SELECT 1 FROM public.conversation_members cm
    JOIN public.conversation_members cm2
      ON cm2.conversation_id = cm.conversation_id
     AND cm2.user_id = auth.uid()
    WHERE cm.user_id = user_privacy_settings.user_id
  )
  AND NOT public.is_blocked_between(auth.uid(), user_privacy_settings.user_id)
);

CREATE POLICY "Users can update own privacy settings"
ON public.user_privacy_settings FOR UPDATE TO authenticated
USING (auth.uid() = user_id)
WITH CHECK (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- contacts policies
-- ---------------------------------------------------------------------------
CREATE POLICY "Users can view own contacts"
ON public.contacts FOR SELECT TO authenticated
USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own contacts"
ON public.contacts FOR INSERT TO authenticated
WITH CHECK (
  auth.uid() = user_id
  AND NOT public.is_blocked_between(auth.uid(), contact_id)
);

CREATE POLICY "Users can delete own contacts"
ON public.contacts FOR DELETE TO authenticated
USING (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- blocked_users policies
-- ---------------------------------------------------------------------------
CREATE POLICY "Users can view own block relationships"
ON public.blocked_users FOR SELECT TO authenticated
USING (auth.uid() = blocker_id OR auth.uid() = blocked_id);

CREATE POLICY "Users can block others"
ON public.blocked_users FOR INSERT TO authenticated
WITH CHECK (auth.uid() = blocker_id);

CREATE POLICY "Users can unblock others"
ON public.blocked_users FOR DELETE TO authenticated
USING (auth.uid() = blocker_id);

-- ---------------------------------------------------------------------------
-- conversations policies
-- ---------------------------------------------------------------------------
CREATE POLICY "Members can view conversations"
ON public.conversations FOR SELECT TO authenticated
USING (public.is_conversation_member(id));

CREATE POLICY "Authenticated users can create conversations"
ON public.conversations FOR INSERT TO authenticated
WITH CHECK (auth.uid() = created_by);

CREATE POLICY "Members can update conversations"
ON public.conversations FOR UPDATE TO authenticated
USING (
  public.is_conversation_member(id)
  AND EXISTS (
    SELECT 1 FROM public.conversation_members
    WHERE conversation_id = conversations.id
      AND user_id = auth.uid()
      AND role = 'admin'
  )
);

-- ---------------------------------------------------------------------------
-- conversation_members policies
-- ---------------------------------------------------------------------------
CREATE POLICY "Members can view conversation members"
ON public.conversation_members FOR SELECT TO authenticated
USING (public.is_conversation_member(conversation_id));

CREATE POLICY "Members can insert conversation members"
ON public.conversation_members FOR INSERT TO authenticated
WITH CHECK (
  auth.uid() = user_id
  AND public.is_conversation_member(conversation_id)
);

CREATE POLICY "Admins can update conversation members"
ON public.conversation_members FOR UPDATE TO authenticated
USING (
  public.is_conversation_member(conversation_id)
  AND EXISTS (
    SELECT 1 FROM public.conversation_members cm
    WHERE cm.conversation_id = conversation_members.conversation_id
      AND cm.user_id = auth.uid()
      AND cm.role = 'admin'
  )
);

CREATE POLICY "Members can leave or be removed from conversations"
ON public.conversation_members FOR DELETE TO authenticated
USING (
  auth.uid() = user_id
  OR EXISTS (
    SELECT 1 FROM public.conversation_members cm
    WHERE cm.conversation_id = conversation_members.conversation_id
      AND cm.user_id = auth.uid()
      AND cm.role = 'admin'
  )
);

-- ---------------------------------------------------------------------------
-- messages policies
-- ---------------------------------------------------------------------------
CREATE POLICY "Members can view messages"
ON public.messages FOR SELECT TO authenticated
USING (
  public.is_conversation_member(conversation_id)
  AND NOT public.is_blocked_between(auth.uid(), sender_id)
  AND (deleted_for_everyone = false OR auth.uid() = sender_id)
);

CREATE POLICY "Members can insert messages"
ON public.messages FOR INSERT TO authenticated
WITH CHECK (
  auth.uid() = sender_id
  AND public.is_conversation_member(conversation_id)
  AND NOT EXISTS (
    SELECT 1 FROM public.conversation_members cm
    WHERE cm.conversation_id = messages.conversation_id
      AND cm.user_id <> auth.uid()
      AND public.is_blocked_between(auth.uid(), cm.user_id)
  )
);

CREATE POLICY "Senders can update own messages"
ON public.messages FOR UPDATE TO authenticated
USING (auth.uid() = sender_id)
WITH CHECK (auth.uid() = sender_id);

-- ---------------------------------------------------------------------------
-- message_receipts policies
-- ---------------------------------------------------------------------------
CREATE POLICY "Members can view message receipts"
ON public.message_receipts FOR SELECT TO authenticated
USING (
  public.is_conversation_member(
    (SELECT conversation_id FROM public.messages WHERE id = message_receipts.message_id)
  )
);

CREATE POLICY "Users can insert own receipts"
ON public.message_receipts FOR INSERT TO authenticated
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own receipts"
ON public.message_receipts FOR UPDATE TO authenticated
USING (auth.uid() = user_id)
WITH CHECK (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- Function: cleanup expired (disappearing) messages
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.cleanup_expired_messages()
RETURNS void AS $$
BEGIN
  DELETE FROM public.messages
  WHERE expires_at IS NOT NULL AND expires_at < now();
END;
$$ LANGUAGE plpgsql;
