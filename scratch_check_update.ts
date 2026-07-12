import dotenv from "dotenv";
import path from "path";

async function run() {
  dotenv.config({ path: path.resolve(process.cwd(), ".env.development.local") });
  dotenv.config({ path: path.resolve(process.cwd(), ".env.local") });

  const { createClient } = await import("@supabase/supabase-js");

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    console.error("Missing remote Supabase credentials in env files!");
    process.exit(1);
  }

  const db = createClient(url, key, {
    auth: { persistSession: false },
  });

  const investigationId = "bdaf5a17-8acf-40f5-bc6e-f04903b5d7d2";

  console.log(`Executing exact update statement for case ${investigationId}...`);
  const res = await db.from("investigations").update({
    status: "COMPLETED",
    final_score: 14,
    scoring_profile_version: null,
    failed_sources: [
      {
        "reason": "AbuseIPDB API error 401: {\"errors\":[{\"detail\":\"Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key.\",\"status\":401}]}",
        "source": "abuseipdb"
      }
    ],
    completed_at: new Date().toISOString(),
  }).eq("id", investigationId).select();

  console.log("Update response:", JSON.stringify(res, null, 2));
}

run().catch(console.error);
