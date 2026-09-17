-- Drop the retired paid lane's quote table (created by 0007). The lane never
-- quoted in any deployment, so the table holds nothing. The guard refuses the
-- drop if that ever turns out to be wrong: a row here may record money received.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM payment_requests) THEN
        RAISE EXCEPTION 'payment_requests is not empty; export it before dropping';
    END IF;
END
$$;

DROP TABLE payment_requests;
