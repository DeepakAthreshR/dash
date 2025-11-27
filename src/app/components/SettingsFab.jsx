import Fab from "@mui/material/Fab";
import Settings from "@mui/icons-material/Settings";
import styled from "@mui/material/styles/styled";

const FabContainer = styled("div")(() => ({
  zIndex: 99,
  right: "30px",
  bottom: "50px",
  position: "fixed"
}));

export default function SettingsFab() {
  return (
    <FabContainer>
      <Fab color="primary" aria-label="settings">
        <Settings sx={{ color: "primary.contrastText" }} />
      </Fab>
    </FabContainer>
  );
} 