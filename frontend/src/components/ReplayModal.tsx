import { useEffect, useState, useRef, ChangeEvent, DragEvent } from "react";
import {
  PlayIcon,
  Upload01Icon as UploadIcon,
  CheckmarkCircle02Icon as CheckIcon,
  AlertCircleIcon as AlertIcon,
  Loading02Icon as SpinnerIcon,
  Cancel01Icon as CloseIcon,
  File01Icon as FileIcon,
  Layers01Icon as DatabaseIcon,
  Tag01Icon as TagIcon,
} from "hugeicons-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface PcapMetadata {
  filename: string;
  size_bytes: number;
  created_at: string;
  attack_tag: string;
}

interface ReplayJobStatus {
  job_id: string;
  filename: string;
  status: "queued" | "processing" | "completed" | "failed";
  total_flows: number;
  published_records: number;
  started_at?: string;
  completed_at?: string;
  error?: string;
}

interface ReplayModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ReplayModal({ open, onOpenChange }: ReplayModalProps) {
  const [pcaps, setPcaps] = useState<PcapMetadata[]>([]);
  const [loadingPcaps, setLoadingPcaps] = useState<boolean>(false);
  const [activeJob, setActiveJob] = useState<ReplayJobStatus | null>(null);
  const [uploading, setUploading] = useState<boolean>(false);
  const [dragActive, setDragActive] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchPcaps = async () => {
    setLoadingPcaps(true);
    try {
      const res = await fetch("/api/replay/pcaps");
      if (res.ok) {
        const data = await res.json();
        setPcaps(data);
      }
    } catch (err) {
      console.error("Failed to load pcaps:", err);
    } finally {
      setLoadingPcaps(false);
    }
  };

  useEffect(() => {
    if (open) {
      fetchPcaps();
    }
  }, [open]);

  // Live polling for active replay job status
  useEffect(() => {
    if (!activeJob || activeJob.status === "completed" || activeJob.status === "failed") {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/replay/status/${activeJob.job_id}`);
        if (res.ok) {
          const statusData: ReplayJobStatus = await res.json();
          setActiveJob(statusData);

          if (statusData.status === "completed") {
            setToastMessage({
              text: `Replay Complete: Ingested ${statusData.total_flows} flows (${statusData.published_records} events) into Redpanda/Kafka.`,
              type: "success",
            });
          } else if (statusData.status === "failed") {
            setToastMessage({
              text: `Replay Failed: ${statusData.error || "Unknown execution error"}`,
              type: "error",
            });
          }
        }
      } catch (err) {
        console.error("Failed to poll replay status:", err);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [activeJob]);

  const handleTriggerReplay = async (filename: string) => {
    try {
      setToastMessage(null);
      const res = await fetch("/api/replay/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename }),
      });

      if (res.ok) {
        const data = await res.json();
        setActiveJob({
          job_id: data.job_id,
          filename: filename,
          status: "processing",
          total_flows: 0,
          published_records: 0,
        });
      } else {
        const errData = await res.json();
        setToastMessage({
          text: `Trigger Error: ${errData.detail || "Failed to launch replay"}`,
          type: "error",
        });
      }
    } catch (err) {
      setToastMessage({ text: "Failed to communicate with backend replay API.", type: "error" });
    }
  };

  const handleFileUpload = async (file: File) => {
    if (!file.name.endsWith(".pcap") && !file.name.endsWith(".pcapng")) {
      setToastMessage({ text: "Invalid file type. Only .pcap and .pcapng files are supported.", type: "error" });
      return;
    }

    setUploading(true);
    setToastMessage(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("/api/replay/upload", {
        method: "POST",
        body: formData,
      });

      if (res.ok) {
        const result = await res.json();
        setToastMessage({ text: `Uploaded capture: ${result.filename}`, type: "success" });
        fetchPcaps();
      } else {
        const errData = await res.json();
        setToastMessage({ text: errData.detail || "Upload validation failed.", type: "error" });
      }
    } catch (err) {
      setToastMessage({ text: "Error uploading PCAP file.", type: "error" });
    } finally {
      setUploading(false);
    }
  };

  const handleDrag = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-3xl rounded-xl border border-zinc-800 bg-[#090d16] p-6 shadow-2xl space-y-6 text-zinc-100 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-zinc-800/80 pb-4">
          <div className="flex items-center space-x-3">
            <div className="flex items-center justify-center h-10 w-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <PlayIcon className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-bold font-sans tracking-wide uppercase text-zinc-100">
                Automated PCAP Replay & Forensics
              </h2>
              <p className="text-xs text-zinc-400 font-mono">
                On-Demand Zeek Container Ingestion & Redpanda Log Shipper
              </p>
            </div>
          </div>
          <button
            onClick={() => onOpenChange(false)}
            className="rounded-lg p-1.5 text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition-colors"
          >
            <CloseIcon className="h-5 w-5" />
          </button>
        </div>

        {/* Toast Notification Alert */}
        {toastMessage && (
          <div
            className={`flex items-center justify-between px-4 py-2.5 rounded-lg border text-xs font-mono ${
              toastMessage.type === "success"
                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                : "bg-rose-500/10 border-rose-500/30 text-rose-300"
            }`}
          >
            <div className="flex items-center space-x-2">
              {toastMessage.type === "success" ? (
                <CheckIcon className="h-4 w-4 text-emerald-400" />
              ) : (
                <AlertIcon className="h-4 w-4 text-rose-400" />
              )}
              <span>{toastMessage.text}</span>
            </div>
            <button
              onClick={() => setToastMessage(null)}
              className="text-zinc-400 hover:text-zinc-200 text-xs ml-4"
            >
              ✕
            </button>
          </div>
        )}

        {/* Active Job Execution Progress Bar */}
        {activeJob && (
          <div className="p-4 rounded-lg bg-zinc-900/90 border border-zinc-800 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <div className="flex items-center space-x-2">
                {activeJob.status === "processing" ? (
                  <SpinnerIcon className="h-4 w-4 text-amber-400 animate-spin" />
                ) : activeJob.status === "completed" ? (
                  <CheckIcon className="h-4 w-4 text-emerald-400" />
                ) : (
                  <AlertIcon className="h-4 w-4 text-rose-400" />
                )}
                <span className="font-semibold text-zinc-200">Replaying: {activeJob.filename}</span>
              </div>
              <Badge
                variant="outline"
                className={`font-mono text-[10px] uppercase ${
                  activeJob.status === "processing"
                    ? "border-amber-500/30 bg-amber-500/10 text-amber-400"
                    : activeJob.status === "completed"
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                    : "border-rose-500/30 bg-rose-500/10 text-rose-400"
                }`}
              >
                {activeJob.status}
              </Badge>
            </div>

            {/* Live Progress Bar */}
            <div className="w-full bg-zinc-800 h-2 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${
                  activeJob.status === "completed"
                    ? "bg-emerald-500 w-full"
                    : activeJob.status === "failed"
                    ? "bg-rose-500 w-full"
                    : "bg-amber-400 animate-pulse w-3/4"
                }`}
              />
            </div>

            <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400">
              <div className="flex items-center space-x-4">
                <span>
                  Parsed Flows: <strong className="text-zinc-200">{activeJob.total_flows}</strong>
                </span>
                <span>
                  Published Events: <strong className="text-zinc-200">{activeJob.published_records}</strong>
                </span>
              </div>
              <span className="text-zinc-500">ID: {activeJob.job_id.substring(0, 8)}</span>
            </div>
          </div>
        )}

        {/* Drag and Drop PCAP Uploader */}
        <div
          onDragEnter={handleDrag}
          onDragOver={handleDrag}
          onDragLeave={handleDrag}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`cursor-pointer border-2 border-dashed rounded-lg p-6 text-center transition-colors ${
            dragActive
              ? "border-emerald-500 bg-emerald-500/[0.05]"
              : "border-zinc-800 hover:border-zinc-700 bg-zinc-900/40"
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.pcapng"
            className="hidden"
            onChange={(e: ChangeEvent<HTMLInputElement>) => {
              if (e.target.files && e.target.files[0]) {
                handleFileUpload(e.target.files[0]);
              }
            }}
          />
          <div className="flex flex-col items-center space-y-2">
            {uploading ? (
              <SpinnerIcon className="h-8 w-8 text-emerald-400 animate-spin" />
            ) : (
              <UploadIcon className="h-8 w-8 text-zinc-400" />
            )}
            <p className="text-xs font-mono font-medium text-zinc-300">
              Drag & Drop custom PCAP capture here or <span className="text-emerald-400 underline">browse files</span>
            </p>
            <p className="text-[10px] font-mono text-zinc-500">
              Supports .pcap & .pcapng captures (Magic Header Validated)
            </p>
          </div>
        </div>

        {/* Available Preloaded PCAPs List */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold font-mono text-zinc-400 uppercase tracking-wider flex items-center gap-1.5">
              <DatabaseIcon className="h-3.5 w-3.5" />
              Available Capture Repository ({pcaps.length})
            </h3>
            {loadingPcaps && <SpinnerIcon className="h-3.5 w-3.5 text-zinc-400 animate-spin" />}
          </div>

          <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
            {pcaps.length === 0 ? (
              <p className="text-xs font-mono text-zinc-500 text-center py-4">No PCAP captures found in pcaps/ directory.</p>
            ) : (
              pcaps.map((pcap) => (
                <div
                  key={pcap.filename}
                  className="flex items-center justify-between p-3 rounded-lg bg-zinc-900/80 border border-zinc-800/80 hover:border-zinc-700 transition-colors"
                >
                  <div className="flex items-start space-x-3">
                    <FileIcon className="h-5 w-5 text-emerald-400 mt-0.5" />
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-bold font-mono text-zinc-100">{pcap.filename}</span>
                        <Badge
                          variant="outline"
                          className="border-emerald-500/30 bg-emerald-500/10 text-emerald-300 font-mono text-[10px] gap-1"
                        >
                          <TagIcon className="h-2.5 w-2.5" />
                          {pcap.attack_tag}
                        </Badge>
                      </div>
                      <div className="flex items-center space-x-3 text-[10px] font-mono text-zinc-400 mt-1">
                        <span>{formatBytes(pcap.size_bytes)}</span>
                        <span>•</span>
                        <span>{new Date(pcap.created_at).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>

                  <Button
                    size="sm"
                    onClick={() => handleTriggerReplay(pcap.filename)}
                    disabled={activeJob?.status === "processing"}
                    className="gap-1.5 font-mono text-xs bg-emerald-600 hover:bg-emerald-500 text-white"
                  >
                    <PlayIcon className="h-3.5 w-3.5" />
                    RUN REPLAY
                  </Button>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex justify-end pt-2 border-t border-zinc-800/80">
          <Button
            variant="subtle"
            size="sm"
            onClick={() => onOpenChange(false)}
            className="font-mono text-xs"
          >
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}
