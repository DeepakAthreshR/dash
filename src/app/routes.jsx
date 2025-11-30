import { lazy } from "react";
import { Navigate } from "react-router-dom";

import ParcLayout from "./components/ParcLayout/ParcLayout";

// Lazy load the Deployment Application
const DeploymentApp = lazy(() => import("./views/deployment/DeploymentApp"));

// Dummy components for existing routes
const Dummy1 = () => <div style={{textAlign: 'center', marginTop: '20vh', fontSize: 32}}>Dummy Page 1</div>;
const Dummy2 = () => <div style={{textAlign: 'center', marginTop: '20vh', fontSize: 32}}>Dummy Page 2</div>;

const routes = [
  // Redirect root path to the deployment dashboard
  { path: "/", element: <Navigate to="dashboard/deployment" /> },
  {
    element: <ParcLayout />,
    children: [
      // Map the deployment view to the dashboard path
      { path: "/dashboard/deployment", element: <DeploymentApp /> },
      
      // Existing dummy routes
      { path: "/dummy1", element: <Dummy1 /> },
      { path: "/dummy2", element: <Dummy2 /> }
    ]
  }
];

export default routes;