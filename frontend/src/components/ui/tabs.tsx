import * as React from "react";
import { cn } from "@/lib/utils";

interface TabsContextType {
  value: string;
  onValueChange: (val: string) => void;
}

const TabsContext = React.createContext<TabsContextType>({
  value: "",
  onValueChange: () => {},
});

export function Tabs({
  value,
  defaultValue = "",
  onValueChange,
  className,
  children,
}: {
  value?: string;
  defaultValue?: string;
  onValueChange?: (val: string) => void;
  className?: string;
  children: React.ReactNode;
}) {
  const [internalValue, setInternalValue] = React.useState(value || defaultValue);
  const activeValue = value !== undefined ? value : internalValue;

  const handleValueChange = (val: string) => {
    setInternalValue(val);
    onValueChange?.(val);
  };

  return (
    <TabsContext.Provider value={{ value: activeValue, onValueChange: handleValueChange }}>
      <div className={cn("w-full", className)}>{children}</div>
    </TabsContext.Provider>
  );
}

export function TabsList({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <div
      className={cn(
        "inline-flex h-8 items-center justify-center rounded-md bg-slate-900/90 p-1 text-slate-400 border border-slate-800",
        className
      )}
    >
      {children}
    </div>
  );
}

export function TabsTrigger({
  value,
  className,
  children,
}: {
  value: string;
  className?: string;
  children: React.ReactNode;
}) {
  const { value: selectedValue, onValueChange } = React.useContext(TabsContext);
  const isActive = selectedValue === value;

  return (
    <button
      type="button"
      onClick={() => onValueChange(value)}
      className={cn(
        "inline-flex items-center justify-center whitespace-nowrap rounded-sm px-2.5 py-1 text-xs font-medium ring-offset-background transition-all focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50",
        isActive
          ? "bg-slate-800 text-cyan-400 shadow-sm font-semibold"
          : "hover:bg-slate-850 hover:text-slate-200 text-slate-400",
        className
      )}
    >
      {children}
    </button>
  );
}

export function TabsContent({
  value,
  className,
  children,
}: {
  value: string;
  className?: string;
  children: React.ReactNode;
}) {
  const { value: selectedValue } = React.useContext(TabsContext);
  if (selectedValue !== value) return null;

  return (
    <div className={cn("mt-2 ring-offset-background focus-visible:outline-none", className)}>
      {children}
    </div>
  );
}
