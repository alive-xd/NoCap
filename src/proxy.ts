import { type NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { isLocalMode } from "@/lib/supabase/local";

export async function proxy(request: NextRequest) {
  // CSRF validation for mutating endpoints using cookie-based auth
  const mutatingMethods = ["POST", "PUT", "PATCH", "DELETE"];
  if (mutatingMethods.includes(request.method)) {
    const origin = request.headers.get("origin");
    const referer = request.headers.get("referer");
    const host = request.headers.get("host") ?? request.nextUrl.host;
    
    let originHost: string | null = null;
    if (origin) {
      try {
        originHost = new URL(origin).host;
      } catch {}
    }
    
    let refererHost: string | null = null;
    if (referer) {
      try {
        refererHost = new URL(referer).host;
      } catch {}
    }
    
    const isOriginValid = originHost ? originHost === host : true;
    const isRefererValid = refererHost ? refererHost === host : true;
    
    if (!isOriginValid || !isRefererValid) {
      return new NextResponse(
        JSON.stringify({ error: "CSRF verification failed: origin/referer host mismatch" }),
        { status: 403, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  // Safety guard: if Supabase is not yet configured, fail closed.
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const isVercelDeployed = process.env.VERCEL_ENV === "production" || process.env.VERCEL_ENV === "preview";
  
  if (
    isVercelDeployed && 
    (
      !supabaseUrl || supabaseUrl === "https://your-project-id.supabase.co" ||
      !supabaseAnonKey || supabaseAnonKey === "your-anon-key"
    )
  ) {
    return new NextResponse(
      JSON.stringify({ error: "Server configuration error: Supabase is not configured." }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }

  let supabaseResponse = NextResponse.next({ request });
  let user: any = null;

  if (isLocalMode) {
    user = { id: "local-dev-user-id", email: "dev@nocap.local" };
  } else {
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      {
        cookies: {
          getAll() {
            return request.cookies.getAll();
          },
          setAll(cookiesToSet) {
            cookiesToSet.forEach(({ name, value }) =>
              request.cookies.set(name, value)
            );
            supabaseResponse = NextResponse.next({ request });
            cookiesToSet.forEach(({ name, value, options }) =>
              supabaseResponse.cookies.set(name, value, options)
            );
          },
        },
      }
    );

    const authHeader = request.headers.get("Authorization");
    if (authHeader?.startsWith("Bearer ")) {
      const token = authHeader.replace("Bearer ", "");
      const { data: { user: supabaseUser } } = await supabase.auth.getUser(token);
      user = supabaseUser;
    } else {
      const { data: { user: supabaseUser } } = await supabase.auth.getUser();
      user = supabaseUser;
    }
  }

  const { pathname } = request.nextUrl;
  const isAuthRoute = pathname.startsWith("/login") || pathname.startsWith("/auth");
  const isPublicRoute = pathname === "/" || pathname.startsWith("/demo/") || pathname.startsWith("/api/demo/") || pathname.startsWith("/api/cron/");

  // Redirect unauthenticated users to login
  if (!user && !isAuthRoute && !isPublicRoute) {
    if (pathname.startsWith("/api/")) {
      return new NextResponse(
        JSON.stringify({ error: "Unauthorized" }),
        { status: 401, headers: { "Content-Type": "application/json" } }
      );
    }
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = "/login";
    return NextResponse.redirect(loginUrl);
  }

  // Redirect authenticated users away from login
  if (user && isAuthRoute) {
    const dashboardUrl = request.nextUrl.clone();
    dashboardUrl.pathname = "/";
    return NextResponse.redirect(dashboardUrl);
  }

  return supabaseResponse;
}

export default proxy;

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|.*\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
