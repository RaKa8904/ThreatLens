import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap rounded-md text-xs font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-cyan-500 text-slate-950 font-semibold hover:bg-cyan-400 shadow-sm",
        destructive: "bg-destructive text-destructive-foreground hover:bg-destructive/90",
        outline: "border border-slate-800 bg-slate-900/60 hover:bg-slate-800 hover:text-slate-100",
        secondary: "bg-slate-800 text-slate-200 hover:bg-slate-700",
        ghost: "hover:bg-slate-800 hover:text-slate-100",
        link: "text-primary underline-offset-4 hover:underline",
        subtle: "bg-slate-900 border border-slate-800/80 text-slate-300 hover:border-slate-700 hover:bg-slate-850",
      },
      size: {
        default: "h-8 px-3 py-1.5",
        sm: "h-7 rounded px-2 text-xs",
        lg: "h-10 rounded-md px-5 text-sm",
        icon: "h-7 w-7",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => {
    return (
      <button
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

export { Button, buttonVariants };
