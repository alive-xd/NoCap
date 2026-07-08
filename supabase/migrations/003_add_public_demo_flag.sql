ALTER TABLE investigations ADD COLUMN is_public_demo BOOLEAN NOT NULL DEFAULT FALSE;

CREATE POLICY "Public demo investigations are viewable by anyone"
  ON investigations FOR SELECT
  USING (is_public_demo = true);

CREATE POLICY "Public demo artifacts are viewable by anyone"
  ON artifacts FOR SELECT
  USING (
    investigation_id IN (
      SELECT id FROM investigations WHERE is_public_demo = true
    )
  );

CREATE POLICY "Public demo evidence is viewable by anyone"
  ON evidence FOR SELECT
  USING (
    artifact_id IN (
      SELECT a.id FROM artifacts a
      JOIN investigations i ON a.investigation_id = i.id
      WHERE i.is_public_demo = true
    )
  );

CREATE POLICY "Public demo findings are viewable by anyone"
  ON findings FOR SELECT
  USING (
    investigation_id IN (
      SELECT id FROM investigations WHERE is_public_demo = true
    )
  );

CREATE POLICY "Public demo finding_evidence is viewable by anyone"
  ON finding_evidence FOR SELECT
  USING (
    finding_id IN (
      SELECT f.id FROM findings f
      JOIN investigations i ON f.investigation_id = i.id
      WHERE i.is_public_demo = true
    )
  );

CREATE POLICY "Public demo investigation_metrics are viewable by anyone"
  ON investigation_metrics FOR SELECT
  USING (
    investigation_id IN (
      SELECT id FROM investigations WHERE is_public_demo = true
    )
  );
