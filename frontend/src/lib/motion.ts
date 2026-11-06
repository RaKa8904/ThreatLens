import { useEffect, useState } from "react";

export const motionTokens = {
  duration: {
    micro: 0.12,
    standard: 0.18,
    slow: 0.25,
  },
  easing: {
    standard: [0.22, 1, 0.36, 1] as [number, number, number, number], // cubic-bezier
    opacity: "easeOut" as const,
  },
  spring: {
    press: { type: "spring" as const, stiffness: 400, damping: 32 },
  },
};

export function useMotionEnabled() {
  const [enabled, setEnabled] = useState(() => {
    if (typeof window === "undefined") return true;
    const urlParams = new URLSearchParams(window.location.search);
    const motionParam = urlParams.get("motion");
    if (motionParam === "off") return false;
    if (motionParam === "on") return true;
    return !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  });

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const motionParam = urlParams.get("motion");
    if (motionParam === "off") {
      setEnabled(false);
      return;
    }
    if (motionParam === "on") {
      setEnabled(true);
      return;
    }

    const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    setEnabled(!mediaQuery.matches);

    const listener = (event: MediaQueryListEvent) => {
      const currentParams = new URLSearchParams(window.location.search);
      if (!currentParams.get("motion")) {
        setEnabled(!event.matches);
      }
    };

    mediaQuery.addEventListener("change", listener);
    return () => mediaQuery.removeEventListener("change", listener);
  }, []);

  return enabled;
}
