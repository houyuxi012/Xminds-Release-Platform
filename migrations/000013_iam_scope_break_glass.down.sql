ALTER TABLE role_bindings
    DROP CONSTRAINT IF EXISTS role_bindings_channel_scope_fkey,
    DROP CONSTRAINT IF EXISTS role_bindings_channel_name_length,
    DROP CONSTRAINT IF EXISTS role_bindings_product_id_length;
