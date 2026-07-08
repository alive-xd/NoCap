-- 008_restore_pipeline_statuses.sql
-- Restores EXTRACTING_EVIDENCE and RUNNING_ANALYZERS statuses that were accidentally removed in 007.

DO $$
BEGIN
    -- Check if 'ANALYZING' is present in the enum. If it is, we need to fix it.
    IF EXISTS (
        SELECT 1 
        FROM pg_enum 
        WHERE enumtypid = 'investigation_status'::regtype 
        AND enumlabel = 'ANALYZING'
    ) THEN
        -- If there are any rows stuck in 'ANALYZING', move them back to a valid state
        UPDATE investigations SET status = 'FETCHING_ARTIFACTS' WHERE status::text = 'ANALYZING';
        
        -- Create the corrected type
        CREATE TYPE investigation_status_new AS ENUM (
            'CREATED',
            'FETCHING_ARTIFACTS',
            'EXTRACTING_EVIDENCE',
            'RUNNING_ANALYZERS',
            'SCORING',
            'COMPLETED',
            'FAILED'
        );

        -- Swap out the old type
        ALTER TABLE investigations 
            ALTER COLUMN status TYPE investigation_status_new 
            USING status::text::investigation_status_new;

        -- Drop the old type and rename the new one
        DROP TYPE investigation_status;
        ALTER TYPE investigation_status_new RENAME TO investigation_status;
    END IF;
END $$;
