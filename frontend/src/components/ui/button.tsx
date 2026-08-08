import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70 focus-visible:ring-offset-2 focus-visible:ring-offset-canvas disabled:pointer-events-none disabled:opacity-50 cursor-pointer select-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary:
          "bg-primary text-primary-foreground font-semibold hover:brightness-110 shadow-[0_0_20px_-6px_rgba(34,211,238,0.6)]",
        secondary:
          "bg-secondary text-secondary-foreground border border-border hover:bg-surface-overlay",
        outline:
          "border border-border bg-transparent text-foreground hover:bg-surface-overlay/60",
        ghost: "bg-transparent text-muted-foreground hover:bg-surface-overlay/60 hover:text-foreground",
        destructive:
          "bg-destructive text-destructive-foreground font-semibold hover:brightness-110",
        subtle: "bg-primary/10 text-primary hover:bg-primary/20 border border-primary/20",
      },
      size: {
        sm: "h-8 px-3 text-xs",
        md: "h-9 px-4",
        lg: "h-11 px-6 text-base",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />
  )
);
Button.displayName = "Button";

export { buttonVariants };
