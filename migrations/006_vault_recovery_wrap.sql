-- Wrap vault KEK under offline recovery key so lost master password can be reset.
ALTER TABLE vault_meta ADD COLUMN recovery_salt BLOB;
ALTER TABLE vault_meta ADD COLUMN recovery_wrapped_kek BLOB;
