-- Alter enum to add 'CVE' target type
ALTER TYPE target_type ADD VALUE IF NOT EXISTS 'CVE';

-- Enable RLS on scoring_profiles
ALTER TABLE scoring_profiles ENABLE ROW LEVEL SECURITY;

-- Add select policy for authenticated users
CREATE POLICY "Allow authenticated select on scoring_profiles"
  ON scoring_profiles FOR SELECT
  TO authenticated
  USING (true);
