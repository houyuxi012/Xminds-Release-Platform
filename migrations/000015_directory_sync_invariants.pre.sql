-- A canonical mapping registry cannot select a winner for historical email or
-- username collisions without changing identity ownership. Fail before DDL so
-- operators can resolve the conflicting principals explicitly.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM user_principals
        GROUP BY lower(btrim(username)) HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'principal mapping preflight found canonical username conflicts; resolve duplicate principals before migration'
            USING ERRCODE = '23505';
    END IF;
    IF EXISTS (
        SELECT 1 FROM user_principals
        WHERE btrim(email) <> ''
        GROUP BY lower(btrim(email)) HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'principal mapping preflight found canonical email conflicts; resolve duplicate principals before migration'
            USING ERRCODE = '23505';
    END IF;
END $$;
