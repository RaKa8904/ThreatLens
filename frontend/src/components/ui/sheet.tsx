import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

interface SheetContextType {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const SheetContext = React.createContext<SheetContextType>({
  open: false,
  onOpenChange: () => {},
});

export function useSheet() {
  return React.useContext(SheetContext);
}

interface SheetProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  children: React.ReactNode;
}

export function Sheet({ open = false, onOpenChange = () => {}, children }: SheetProps) {
  return (
    <SheetContext.Provider value={{ open, onOpenChange }}>
      {children}
    </SheetContext.Provider>
  );
}

export function SheetTrigger({ children, className }: { children: React.ReactNode; className?: string }) {
  const { onOpenChange } = useSheet();
  return (
    <div className={className} onClick={() => onOpenChange(true)}>
      {children}
    </div>
  );
}

const sheetVariants = cva(
  "fixed z-50 gap-4 bg-slate-900 border-slate-800 p-6 shadow-2xl transition ease-in-out data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:duration-300 data-[state=open]:duration-400",
  {
    variants: {
      side: {
        top: "inset-x-0 top-0 border-b",
        bottom: "inset-x-0 bottom-0 border-t",
        left: "inset-y-0 left-0 h-full w-3/4 border-r sm:max-w-sm",
        right: "inset-y-0 right-0 h-full w-full border-l border-slate-800 sm:max-w-md lg:max-w-lg bg-slate-900/95 backdrop-blur-xl",
      },
    },
    defaultVariants: {
      side: "right",
    },
  }
);

interface SheetContentProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof sheetVariants> {
  children: React.ReactNode;
}

export const SheetContent = React.forwardRef<HTMLDivElement, SheetContentProps>(
  ({ side = "right", className, children, ...props }, ref) => {
    const { open, onOpenChange } = useSheet();

    React.useEffect(() => {
      const handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === "Escape") onOpenChange(false);
      };
      if (open) {
        document.addEventListener("keydown", handleKeyDown);
        document.body.style.overflow = "hidden";
      }
      return () => {
        document.removeEventListener("keydown", handleKeyDown);
        document.body.style.overflow = "unset";
      };
    }, [open, onOpenChange]);

    if (!open) return null;

    return (
      <div className="fixed inset-0 z-50 flex justify-end">
        {/* Backdrop overlay */}
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
          onClick={() => onOpenChange(false)}
        />
        {/* Panel drawer */}
        <div
          ref={ref}
          className={cn(sheetVariants({ side }), "relative z-50 overflow-y-auto", className)}
          {...props}
        >
          {children}
        </div>
      </div>
    );
  }
);
SheetContent.displayName = "SheetContent";

export const SheetHeader = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn("flex flex-col space-y-1.5 text-left border-b border-slate-800/80 pb-4", className)} {...props} />
);

export const SheetTitle = ({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) => (
  <h2 className={cn("text-base font-semibold text-slate-100 tracking-tight", className)} {...props} />
);

export const SheetDescription = ({ className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) => (
  <p className={cn("text-xs text-slate-400", className)} {...props} />
);

export const SheetClose = ({ className, children }: { className?: string; children?: React.ReactNode }) => {
  const { onOpenChange } = useSheet();
  return (
    <button
      type="button"
      onClick={() => onOpenChange(false)}
      className={cn("absolute right-4 top-4 rounded-sm opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:pointer-events-none text-slate-400 hover:text-slate-200", className)}
    >
      {children || "✕"}
    </button>
  );
};
