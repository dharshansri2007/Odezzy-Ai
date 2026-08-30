import { Routes, Route } from 'react-router-dom';
import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { OverviewPage } from '@/pages/dashboard/OverviewPage';
import { ScansPage } from '@/pages/dashboard/ScansPage';
import { FindingsPage } from '@/pages/dashboard/FindingsPage';
import { ServersPage } from '@/pages/dashboard/ServersPage';
import { AttestationPage } from '@/pages/dashboard/AttestationPage';
import { QuarantinePage } from '@/pages/dashboard/QuarantinePage';
import { ReportsPage } from '@/pages/dashboard/ReportsPage';
import { LogsPage } from '@/pages/dashboard/LogsPage';

export default function Dashboard() {
  return (
    <Routes>
      <Route element={<DashboardLayout />}>
        <Route index element={<OverviewPage />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="servers" element={<ServersPage />} />
        <Route path="attestation" element={<AttestationPage />} />
        <Route path="quarantine" element={<QuarantinePage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="logs" element={<LogsPage />} />
      </Route>
    </Routes>
  );
}
