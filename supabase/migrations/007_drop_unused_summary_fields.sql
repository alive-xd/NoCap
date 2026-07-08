DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM investigations WHERE status = 'GENERATING_SUMMARY') THEN
        RAISE EXCEPTION 'Cannot drop GENERATING_SUMMARY: rows still exist with this status';
    END IF;
END $$;

ALTER TABLE investigations DROP COLUMN IF EXISTS summary;

CREATE TYPE investigation_status_new AS ENUM (
  'CREATED',
  'FETCHING_ARTIFACTS',
  'EXTRACTING_EVIDENCE',
  'RUNNING_ANALYZERS',
  'SCORING',
  'COMPLETED',
  'FAILED'
);

ALTER TABLE investigations 
  ALTER COLUMN status TYPE investigation_status_new 
  USING status::text::investigation_status_new;

DROP TYPE investigation_status;
ALTER TYPE investigation_status_new RENAME TO investigation_status;
