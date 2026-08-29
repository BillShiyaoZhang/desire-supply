import type { Metadata } from "next";
import { headers } from "next/headers";
import { PrototypeClient } from "./prototype-client";

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host = requestHeaders.get("x-forwarded-host") ?? requestHeaders.get("host") ?? "localhost:3000";
  const protocol = requestHeaders.get("x-forwarded-proto") ?? (host.startsWith("localhost") ? "http" : "https");
  const origin = `${protocol}://${host}`;

  return {
    title: "愿作 · 制度原型",
    description: "用完全合成的数据演练一段可拒绝、可追溯、可救济的受控协作。",
    metadataBase: new URL(origin),
    openGraph: {
      title: "愿作 · 制度原型",
      description: "合成数据 / 非生产。检查协作何时可以继续、何时必须停下。",
      type: "website",
      images: [{ url: `${origin}/og.png`, width: 1672, height: 941, alt: "愿作制度原型——合成数据，非生产" }],
    },
    twitter: {
      card: "summary_large_image",
      title: "愿作 · 制度原型",
      description: "合成数据 / 非生产",
      images: [`${origin}/og.png`],
    },
  };
}

export default function Home() {
  return <PrototypeClient />;
}
