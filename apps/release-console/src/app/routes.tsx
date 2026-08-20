import { Skeleton } from 'antd';
import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from '../layout/AppShell';

const OverviewPage = lazy(() =>
  import('../pages/overview/OverviewPage').then((module) => ({ default: module.OverviewPage })),
);
const ProductsPage = lazy(() =>
  import('../pages/products/ProductsPage').then((module) => ({ default: module.ProductsPage })),
);
const ProductCreatePage = lazy(() =>
  import('../pages/products/ProductCreatePage').then((module) => ({
    default: module.ProductCreatePage,
  })),
);
const ArtifactsPage = lazy(() =>
  import('../pages/artifacts/ArtifactsPage').then((module) => ({ default: module.ArtifactsPage })),
);
const ReleasesPage = lazy(() =>
  import('../pages/releases/ReleasesPage').then((module) => ({ default: module.ReleasesPage })),
);
const ReleaseDetailPage = lazy(() =>
  import('../pages/releases/ReleaseDetailPage').then((module) => ({
    default: module.ReleaseDetailPage,
  })),
);
const ScmPage = lazy(() =>
  import('../pages/scm/ScmPage').then((module) => ({ default: module.ScmPage })),
);
const EndpointsPage = lazy(() =>
  import('../pages/endpoints/EndpointsPage').then((module) => ({ default: module.EndpointsPage })),
);
const AuditPage = lazy(() =>
  import('../pages/audit/AuditPage').then((module) => ({ default: module.AuditPage })),
);

export function ConsoleRoutes() {
  return (
    <AppShell>
      <Suspense fallback={<Skeleton active paragraph={{ rows: 8 }} style={{ padding: 24 }} />}>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/products" element={<ProductsPage />} />
          <Route path="/products/new" element={<ProductCreatePage />} />
          <Route path="/artifacts" element={<ArtifactsPage />} />
          <Route path="/releases" element={<ReleasesPage />} />
          <Route path="/releases/:releaseId" element={<ReleaseDetailPage />} />
          <Route path="/scm" element={<ScmPage />} />
          <Route path="/endpoints" element={<EndpointsPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </AppShell>
  );
}
