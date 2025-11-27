import { Suspense } from "react";
import { ParcLoading } from "app/components";

export default function ParcSuspense({ children }) {
  return <Suspense fallback={<ParcLoading />}>{children}</Suspense>;
}
