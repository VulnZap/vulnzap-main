-- Create a table for user scan history
CREATE TABLE IF NOT EXISTS user_scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  package_name TEXT NOT NULL,
  package_version TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  status TEXT NOT NULL, -- 'vulnerable', 'safe', 'unknown', 'error'
  vulnerability_count INT NOT NULL DEFAULT 0,
  scan_result JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create an index for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_scans_user_id ON user_scans (user_id);
CREATE INDEX IF NOT EXISTS idx_user_scans_package ON user_scans (package_name, ecosystem);
CREATE INDEX IF NOT EXISTS idx_user_scans_created_at ON user_scans (created_at);

-- Add row level security policies
ALTER TABLE user_scans ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view only their own scans
CREATE POLICY "Users can view their own scans"
  ON user_scans FOR SELECT
  USING (auth.uid() = user_id);

-- Policy: Users can insert their own scans
CREATE POLICY "Users can insert their own scans"
  ON user_scans FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Create a function to count vulnerability scans
CREATE OR REPLACE FUNCTION get_user_scan_stats(p_user_id UUID)
RETURNS TABLE (
  total_scans BIGINT,
  vulnerable_packages BIGINT,
  unique_packages BIGINT
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    COUNT(*)::BIGINT AS total_scans,
    COUNT(*) FILTER (WHERE status = 'vulnerable')::BIGINT AS vulnerable_packages,
    COUNT(DISTINCT (package_name || ':' || ecosystem))::BIGINT AS unique_packages
  FROM
    user_scans
  WHERE
    user_id = p_user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER; 