"use client";

import { createBrowserClient } from "@supabase/ssr";
import { createLocalClient, isLocalMode } from "./local";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function createClient(): any {
  if (isLocalMode) {
    return createLocalClient();
  }
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  );
}
