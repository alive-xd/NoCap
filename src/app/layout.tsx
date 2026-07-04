import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NoCap — Threat Intelligence Investigation Platform",
  description:
    "Investigate IOCs, phishing attempts, and attack surfaces with a structured evidence-backed pipeline. Every finding is traceable to the exact data that produced it.",
  keywords: [
    "threat intelligence",
    "IOC investigation",
    "malware analysis",
    "phishing detection",
    "attack surface",
    "security operations",
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Spectral:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&family=IBM+Plex+Sans:wght@300;400;500;600&family=IBM+Plex+Mono:wght@300;400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}

