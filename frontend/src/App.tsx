import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AnimatePresence } from "framer-motion";
import { AppLayout } from "@/components/layout/AppLayout";
import { InvestigationLayout } from "@/components/shared/InvestigationLayout";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import Upload from "@/pages/Upload";
import Queue from "@/pages/Queue";
import StaticAnalysisPage from "@/pages/analysis/StaticAnalysis";
import DynamicAnalysisPage from "@/pages/analysis/DynamicAnalysis";
import NetworkAnalysisPage from "@/pages/analysis/NetworkAnalysis";
import ThreatIntelPage from "@/pages/analysis/ThreatIntel";
import MitrePage from "@/pages/analysis/Mitre";
import AiInvestigationPage from "@/pages/analysis/AiInvestigation";
import ReportPage from "@/pages/analysis/Report";

function RequireAuth({ children }: { children: JSX.Element }) {
  const authed = sessionStorage.getItem("aegis-auth") === "true";
  const location = useLocation();
  if (!authed) return <Navigate to="/login" state={{ from: location }} replace />;
  return children;
}

export default function App() {
  const location = useLocation();
  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/login" element={<Login />} />

        <Route
          element={
            <RequireAuth>
              <AppLayout />
            </RequireAuth>
          }
        >
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/upload" element={<Upload />} />
          <Route path="/queue" element={<Queue />} />

          <Route path="/investigation/:id" element={<InvestigationLayout />}>
            <Route index element={<Navigate to="static" replace />} />
            <Route path="static" element={<StaticAnalysisPage />} />
            <Route path="dynamic" element={<DynamicAnalysisPage />} />
            <Route path="network" element={<NetworkAnalysisPage />} />
            <Route path="intel" element={<ThreatIntelPage />} />
            <Route path="mitre" element={<MitrePage />} />
            <Route path="ai" element={<AiInvestigationPage />} />
            <Route path="report" element={<ReportPage />} />
          </Route>
        </Route>

        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </AnimatePresence>
  );
}
