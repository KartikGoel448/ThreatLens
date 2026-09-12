import React from 'react';
import { ShieldCheck, Info } from 'lucide-react';

interface ToastProps {
  message: string | null;
}

export const Toast: React.FC<ToastProps> = ({ message }) => {
  if (!message) return null;

  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-[99] max-w-[90vw] bg-[#0e1a2c] border border-[#1f5a72] text-[#cfeefb] px-5 py-3 rounded-xl font-semibold text-sm shadow-[0_12px_34px_rgba(0,0,0,0.5)] flex items-center gap-2.5 animate-[fadeIn_0.2s_ease-out] no-print">
      <Info className="w-4 h-4 text-[#3fd0f0] shrink-0" />
      <span>{message}</span>
    </div>
  );
};
