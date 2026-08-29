import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "愿作 · 制度原型",
  description: "完全合成、可重置、非生产的制度评审工作台。",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
