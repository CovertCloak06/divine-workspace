import { Route, Routes } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import CreateSite from './pages/CreateSite';
import SitePlanner from './pages/SitePlanner';
import PlanReview from './pages/PlanReview';
import TruckProfiles from './pages/TruckProfiles';
import SharedPlan from './pages/SharedPlan';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Dashboard />} />
      <Route path="/sites/new" element={<CreateSite />} />
      <Route path="/sites/:siteId" element={<SitePlanner />} />
      <Route path="/sites/:siteId/plan/:planId" element={<PlanReview />} />
      <Route path="/trucks" element={<TruckProfiles />} />
      <Route path="/shared/:payload" element={<SharedPlan />} />
    </Routes>
  );
}
