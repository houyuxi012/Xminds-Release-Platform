ALTER TABLE role_bindings
    ADD CONSTRAINT role_bindings_product_id_length
        CHECK (product_id IS NULL OR length(product_id) <= 128),
    ADD CONSTRAINT role_bindings_channel_name_length
        CHECK (channel_name IS NULL OR length(channel_name) <= 64),
    ADD CONSTRAINT role_bindings_channel_scope_fkey
        FOREIGN KEY (product_id, channel_name)
        REFERENCES product_channels(product_id, name)
        ON DELETE RESTRICT;
