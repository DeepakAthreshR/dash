import { ParcSuspense } from "app/components";
import useSettings from "app/hooks/useSettings";
import { ParcLayouts } from "./index";

export default function ParcLayout(props) {
  const { settings } = useSettings();
  const Layout = ParcLayouts[settings.activeLayout];

  return (
    <ParcSuspense>
      <Layout {...props} />
    </ParcSuspense>
  );
}
