-- Heartbeats from Hound agents
CREATE TABLE heartbeats (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  agent_id TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  agent_version TEXT,
  macos_version TEXT,
  uptime_seconds INTEGER,
  incidents_24h INTEGER DEFAULT 0,
  simulation_mode BOOLEAN DEFAULT true,
  rss_mb REAL,
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL
);

-- Index for fast queries by agent and time
CREATE INDEX idx_heartbeats_agent_id ON heartbeats(agent_id);
CREATE INDEX idx_heartbeats_created_at ON heartbeats(created_at DESC);

-- Only keep 30 days of heartbeats
CREATE OR REPLACE FUNCTION delete_old_heartbeats()
RETURNS void AS $$
BEGIN
  DELETE FROM heartbeats WHERE created_at < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;
