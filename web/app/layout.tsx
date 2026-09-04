import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "愿作 · 内部试运行工作台",
  description: "愿作内部工作台：从待办开始，管理需求、画像、审核与合作进展。",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
