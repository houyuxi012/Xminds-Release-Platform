export const productManifestFixture = {
  schema_version: 'xminds-product-manifest/v1' as const,
  product_id: 'ngep',
  display_name: 'Next-Gen Enterprise Portal',
  artifact_types: ['macos-dmg', 'windows-msi'],
  version_scheme: 'semver' as const,
  compatibility_keys: ['platform', 'architecture'],
  catalog_format: 'xminds-tuf-v1' as const,
  default_channels: [{ name: 'stable', display_name: 'Stable' }],
};

export const apiProductFixture = {
  id: 'ngep',
  display_name: 'Next-Gen Enterprise Portal',
  schema_version: 'xminds-product-manifest/v1',
  artifact_types: ['macos-dmg', 'windows-msi'],
  version_scheme: 'semver',
  compatibility_keys: ['platform', 'architecture'],
  catalog_format: 'xminds-tuf-v1',
  manifest: productManifestFixture,
  manifest_digest: '8b9c7a1200000000000000000000000000000000000000000000000000000000',
  status: 'active',
  channels: [
    {
      product_id: 'ngep',
      name: 'stable',
      display_name: 'Stable',
      position: 0,
      created_at: '2026-08-30T02:00:00Z',
    },
  ],
  created_by: '0198a3b1-6c00-7f11-8000-000000000002',
  created_at: '2026-08-30T02:00:00Z',
  updated_at: '2026-08-30T02:30:00Z',
};
