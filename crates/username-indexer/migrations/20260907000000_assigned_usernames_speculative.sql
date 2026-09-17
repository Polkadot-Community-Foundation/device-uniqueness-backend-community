-- Speculative rows: indexed from the best (unfinalized) chain so a newly
-- registered username reaches search a finality trail earlier — measured at
-- 2–5 blocks on the People chain this indexer reads.
--
-- NULL means the row is confirmed: the finalized pass wrote it, and only the
-- finalized pass may change or remove it. Non-NULL records the best-block
-- number the row was first admitted at — it is not refreshed on later passes,
-- so the age of a pending row stays readable — and marks the row as the only
-- kind speculation is allowed to touch. That asymmetry is the whole safety
-- argument — speculation may add, and may retract what it added, but can never
-- delete or overwrite finalized state on the strength of a fork that may lose.
--
-- The column is also what makes a crash safe. A block seen at the tip is
-- discarded regularly (on PreviewNet's People chain, structurally, roughly one
-- height in eight), and a registration from a losing fork leaves no canonical
-- event for the finalized pass to ever touch that account again. Without a
-- durable mark, such a row would survive a restart forever.
ALTER TABLE assigned_usernames
    ADD COLUMN speculative_from_block BIGINT
    CONSTRAINT assigned_usernames_speculative_from_block_valid
    CHECK (speculative_from_block IS NULL OR speculative_from_block >= 0);

-- Partial: only speculative rows are ever looked up this way, and there are at
-- most a finality trail's worth of them.
CREATE INDEX assigned_usernames_speculative_idx
    ON assigned_usernames (speculative_from_block)
    WHERE speculative_from_block IS NOT NULL;
