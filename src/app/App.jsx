import { useRoutes } from "react-router-dom";
import CssBaseline from "@mui/material/CssBaseline";
// ROOT THEME PROVIDER
import { ParcTheme } from "./components";
// ALL CONTEXTS
import SettingsProvider from "./contexts/SettingsContext";
// ROUTES
import routes from "./routes";
// import "../__api__"; // Removed, API folder deleted

export default function App() {
  const content = useRoutes(routes);

  return (
    <SettingsProvider>
      <ParcTheme>
        <CssBaseline />
        {content}
      </ParcTheme>
    </SettingsProvider>
  );
}
