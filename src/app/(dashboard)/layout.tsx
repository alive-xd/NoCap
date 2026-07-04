import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import DashboardNav from "@/components/DashboardNav";

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) redirect("/login");

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "var(--bg-base)" }}>
      <DashboardNav userEmail={user.email ?? ""} />
      <main
        style={{
          flex: 1,
          marginLeft: "220px",
          minHeight: "100vh",
          padding: "0",
          overflow: "auto",
        }}
      >
        {children}
      </main>
    </div>
  );
}
