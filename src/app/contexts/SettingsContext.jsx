import { createContext, useState } from "react";
import merge from "lodash/merge";
// CUSTOM COMPONENT
import { ParcLayoutSettings } from "app/components/ParcLayout/settings";

export const SettingsContext = createContext({
  settings: ParcLayoutSettings,
  updateSettings: () => {}
});

export default function SettingsProvider({ settings, children }) {
  const [currentSettings, setCurrentSettings] = useState(settings || ParcLayoutSettings);

  const handleUpdateSettings = (update = {}) => {
    const merged = merge({}, currentSettings, update);
    setCurrentSettings(merged);
  };

  return (
    <SettingsContext.Provider
      value={{ settings: currentSettings, updateSettings: handleUpdateSettings }}>
      {children}
    </SettingsContext.Provider>
  );
}
