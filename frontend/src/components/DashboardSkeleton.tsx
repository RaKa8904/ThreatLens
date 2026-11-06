export function DashboardSkeleton() {
  return (
    <div className="flex-1 flex flex-col gap-4 animate-in fade-in duration-150">
      {/* 1. Hero Stat Row Skeleton */}
      <div className="grid grid-cols-1 lg:grid-cols-[1.4fr_1fr_1fr_1.2fr] border-b border-[var(--hairline)] py-4 gap-0">
        {[
          { labelW: "w-28", numW: "w-16", capW: "w-24" },
          { labelW: "w-24", numW: "w-14", capW: "w-24" },
          { labelW: "w-28", numW: "w-20", capW: "w-32" },
          { labelW: "w-24", numW: "w-32", capW: "w-28" },
        ].map((item, idx) => (
          <div
            key={idx}
            className={`flex flex-col pr-6 lg:pr-8 ${
              idx > 0 ? "px-6 lg:px-8 border-r border-transparent lg:border-[var(--hairline)]" : "border-r border-transparent lg:border-[var(--hairline)]"
            } ${idx === 3 ? "pl-6 lg:pl-8 border-r-0" : ""}`}
          >
            <div className={`h-[14px] ${item.labelW} bg-[var(--bg-surface)] rounded motion-safe:animate-pulse mb-2`} />
            <div className={`h-[40px] ${item.numW} bg-[var(--bg-surface)] rounded motion-safe:animate-pulse`} />
            <div className={`h-[14px] ${item.capW} bg-[var(--bg-surface)] rounded motion-safe:animate-pulse mt-2`} />
          </div>
        ))}
      </div>

      {/* 2. Vitals Band Skeleton (Throughput + System Health) */}
      <div className="border border-[var(--hairline)] rounded-md flex flex-col xl:grid xl:grid-cols-[5fr_7fr]">
        <div className="min-w-0 p-5 border-b xl:border-b-0 xl:border-r border-[var(--hairline)] flex flex-col gap-4">
          <div className="h-[20px] w-24 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
          <div className="grid grid-cols-[auto_1fr] gap-[24px] items-center">
            <div className="h-[40px] w-32 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
            <div className="h-[52px] w-full bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
          </div>
        </div>
        <div className="min-w-0 p-5 flex flex-col gap-4">
          <div className="h-[20px] w-20 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
          <div className="grid grid-cols-5 divide-x divide-[var(--hairline)] w-full">
            {[1, 2, 3, 4, 5].map((col) => (
              <div key={col} className="px-3 flex flex-col gap-2">
                <div className="h-[12px] w-16 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
                <div className="h-[18px] w-12 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 3. Trends & Incidents Skeleton */}
      <div className="flex flex-col xl:grid xl:grid-cols-[7fr_5fr] gap-4 xl:h-[220px]">
        <div className="border border-[var(--hairline)] rounded-md p-4 flex flex-col gap-3 h-[220px]">
          <div className="h-[16px] w-28 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
          <div className="flex-1 w-full bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
        </div>
        <div className="border border-[var(--hairline)] rounded-md p-4 flex flex-col gap-3 h-[220px]">
          <div className="h-[16px] w-24 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
          <div className="flex flex-col gap-2 flex-1">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-[32px] w-full bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
            ))}
          </div>
        </div>
      </div>

      {/* 4. Table Toolbar + Rows Skeleton */}
      <div className="flex flex-col gap-2 mt-2">
        <div className="flex items-center justify-between pb-2">
          <div className="h-[32px] w-48 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
          <div className="h-[32px] w-64 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
        </div>
        <div className="border-t border-[var(--hairline)] min-w-[1080px]">
          <div className="grid grid-cols-[104px_minmax(300px,520px)_minmax(220px,380px)_104px_140px_124px_88px] justify-between gap-x-4 px-4 py-3 border-b border-[var(--hairline)]">
            {["TIME", "FLOW", "THREAT CLASS", "SEVERITY", "CONFIDENCE", "STATUS", "ACTION"].map((h) => (
              <div key={h} className="h-[14px] w-12 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
            ))}
          </div>
          <div className="flex flex-col divide-y divide-[var(--hairline)]">
            {[1, 2, 3, 4, 5, 6, 7, 8].map((row) => (
              <div
                key={row}
                className="h-[44px] grid grid-cols-[104px_minmax(300px,520px)_minmax(220px,380px)_104px_140px_124px_88px] justify-between gap-x-4 px-4 items-center"
              >
                <div className="h-[14px] w-16 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
                <div className="h-[14px] w-48 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
                <div className="h-[14px] w-36 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
                <div className="h-[20px] w-16 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
                <div className="h-[14px] w-24 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
                <div className="h-[14px] w-16 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse" />
                <div className="h-[14px] w-8 bg-[var(--bg-surface)] rounded motion-safe:animate-pulse ml-auto" />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
