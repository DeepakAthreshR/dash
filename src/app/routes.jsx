import { lazy } from "react";
import { Navigate } from "react-router-dom";

import ParcLayout from "./components/ParcLayout/ParcLayout";
import DefaultDashboard from "./views/dashboard/DefaultDashboard";
// import Demo from "./components/Demo";

const Dummy1 = () => <div style={{textAlign: 'center', marginTop: '20vh', fontSize: 32}}>Dummy Page 1</div>;
const Dummy2 = () => <div style={{textAlign: 'center', marginTop: '20vh', fontSize: 32}}>Dummy Page 2</div>;

const routes = [
  { path: "/", element: <Navigate to="dashboard/default" /> },
  {
    element: <ParcLayout />,
    children: [
      { path: "/dashboard/default", element: <DefaultDashboard /> },
      { path: "/dummy1", element: <Dummy1 /> },
      { path: "/dummy2", element: <Dummy2 /> }
    ]
  }
];

export default routes;
