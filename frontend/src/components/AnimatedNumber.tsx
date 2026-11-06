import { useEffect, useRef, useState } from "react";
import { animate } from "motion/react";
import { useMotionEnabled } from "@/lib/motion";

export function AnimatedNumber({ value, format = (v) => Math.round(v).toString() }: { value: number, format?: (v: number) => string }) {
  const nodeRef = useRef<HTMLSpanElement>(null);
  const motionEnabled = useMotionEnabled();
  
  // Throttle target value to 4 updates per sec
  const [targetValue, setTargetValue] = useState(value);
  const lastUpdateRef = useRef(0);
  
  useEffect(() => {
    const now = performance.now();
    if (now - lastUpdateRef.current < 250) {
      const timeout = setTimeout(() => {
        setTargetValue(value);
        lastUpdateRef.current = performance.now();
      }, 250 - (now - lastUpdateRef.current));
      return () => clearTimeout(timeout);
    } else {
      setTargetValue(value);
      lastUpdateRef.current = now;
    }
  }, [value]);

  useEffect(() => {
    const node = nodeRef.current;
    if (!node) return;
    
    if (!motionEnabled) {
      node.textContent = format(targetValue);
      return;
    }

    // Try parsing existing text for starting value
    let startVal = 0;
    try {
      startVal = parseFloat(node.textContent?.replace(/[^0-9.-]+/g, "") || "0");
    } catch {
      startVal = targetValue;
    }

    const controls = animate(startVal, targetValue, {
      type: "spring",
      stiffness: 400,
      damping: 32,
      onUpdate: (latest) => {
        if (nodeRef.current) {
          nodeRef.current.textContent = format(latest);
        }
      }
    });
    
    return () => controls.stop();
  }, [targetValue, format, motionEnabled]);

  return <span ref={nodeRef} className="tabular-nums">{format(targetValue)}</span>;
}
