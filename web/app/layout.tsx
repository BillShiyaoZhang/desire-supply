import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "愿作 · 内部试运行工作台",
  description: "由平台账号、服务端角色与对象能力驱动的内部试运行工作台。",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
