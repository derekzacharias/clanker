import * as SwitchPrimitive from "@radix-ui/react-switch";

export function Switch({
  id,
  checked,
  onCheckedChange,
  disabled,
  "aria-describedby": describedBy,
}: {
  id?: string;
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
  disabled?: boolean;
  "aria-describedby"?: string;
}) {
  return (
    <SwitchPrimitive.Root
      id={id}
      checked={checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      aria-describedby={describedBy}
      className="relative h-5 w-9 shrink-0 rounded-full border border-border-strong bg-surface-3 transition-colors data-[state=checked]:border-accent data-[state=checked]:bg-accent disabled:opacity-50"
    >
      <SwitchPrimitive.Thumb className="block h-4 w-4 translate-x-0.5 rounded-full bg-surface shadow transition-transform data-[state=checked]:translate-x-[1.125rem] data-[state=checked]:bg-white" />
    </SwitchPrimitive.Root>
  );
}
