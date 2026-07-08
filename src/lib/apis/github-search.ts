/**
 * GitHub Code Search API client.
 *
 * Used by GitHubExposureParser to surface potential leaked secrets
 * tied to a domain in public GitHub repositories.
 *
 * Requires GITHUB_TOKEN (classic personal access token, public_repo scope).
 * Generate at: https://github.com/settings/tokens
 *
 * Rate limits: 30 requests/minute with auth.
 * Docs: https://docs.github.com/en/rest/search/code
 *
 * IMPORTANT: Results are flagged as Evidence for manual review only.
 * GitHubExposureParser never auto-confirms a Finding — human analyst
 * must review and confirm before a Finding is generated.
 */

const GH_BASE = "https://api.github.com";



/**
 * Searches GitHub public code for potential secrets referencing a domain.
 * Queries for API keys, passwords, tokens associated with the domain string.
 */
export async function searchGitHubCode(
  domain: string,
  maxResults = 30
): Promise<Record<string, unknown>> {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error("GITHUB_TOKEN is not configured");
  }

  // Search for common secret patterns referencing the domain
  const query = `"${domain}" (password OR api_key OR secret OR token OR credential) language:json language:yaml language:env`;

  const params = new URLSearchParams({
    q: query,
    per_page: Math.min(maxResults, 100).toString(),
    sort: "indexed",
    order: "desc",
  });

  const response = await fetch(`${GH_BASE}/search/code?${params}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    cache: "no-store",
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => response.statusText);
    throw new Error(
      `GitHub Search API error ${response.status}: ${errorText}`
    );
  }

  return response.json() as Promise<Record<string, unknown>>;
}
