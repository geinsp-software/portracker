import { Check, Loader2 } from "lucide-react";

export function ActionButton({
  type,
  itemKey,
  actionFeedback,
  onClick,
  // eslint-disable-next-line no-unused-vars
  icon: Icon,
  title,
  loading = false,
  size = "md",
}) {
  const feedback = actionFeedback[type];
  const wasClicked = feedback && feedback.key === itemKey;
  const isLoading =
    loading &&
    feedback &&
    feedback.key === itemKey &&
    feedback.status === "loading";

  const sizeClasses = {
    md: "p-2",
    sm: "p-1.5",
  };

  const iconSizeClasses = {
    md: "h-4 w-4",
    sm: "h-3.5 w-3.5",
  };

  const baseClasses = "relative rounded-md transition-colors";

  const colorClasses = wasClicked
    ? "bg-green-100 text-green-700 dark:bg-green-800/50 dark:text-green-300"
    : isLoading
    ? "bg-blue-100 text-blue-600 dark:bg-blue-800/50 dark:text-blue-300 cursor-not-allowed"
    : "bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600";

  return (
    <button
      onClick={onClick}
      title={title}
      className={`${baseClasses} ${colorClasses} ${sizeClasses[size]}`}
      disabled={wasClicked || isLoading}
    >
      <span
        className={
          wasClicked || isLoading
            ? "opacity-0"
            : "opacity-100 transition-opacity"
        }
      >
        <Icon className={iconSizeClasses[size]} />
      </span>

      {isLoading && (
        <span className="absolute inset-0 flex items-center justify-center">
          <Loader2 className={`${iconSizeClasses[size]} animate-spin`} />
        </span>
      )}

      {wasClicked && (
        <span className={`absolute inset-0 flex items-center justify-center`}>
          <Check className={iconSizeClasses[size]} />
        </span>
      )}
    </button>
  );
}
