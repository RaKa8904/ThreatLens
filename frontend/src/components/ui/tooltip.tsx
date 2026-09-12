import * as React from "react";
import { cn } from "@/lib/utils";

interface TooltipProps {
  content: string | React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export function Tooltip({ content, children, className }: TooltipProps) {
  const [visible, setVisible] = React.useState(false);

  return (
    <div
      className="relative inline-flex items-center"
      onMouseEnter={() => setVisible(true)}
      onMouseLeave={() => setVisible(false)}
    >
      {children}
      {visible && (
        <div
          className={cn(
            "absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5 z-50 overflow-hidden rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-200 shadow-md border border-slate-700 whitespace-nowrap animate-in fade-in-0 zoom-in-95 pointer-events-none",
            className
          )}
        >
          {content}
        </div>
      )}
    </div>
  );
}
