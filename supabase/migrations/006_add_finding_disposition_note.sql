-- Add disposition_note to findings
ALTER TABLE public.findings ADD COLUMN disposition_note TEXT;

-- RLS for findings is already configured with FOR ALL which applies to UPDATE.
-- The existing policy "Users access their findings" ensures updates are only allowed
-- on findings belonging to an investigation owned by the current user.
