import { test, expect } from '@playwright/test';
import { createClient } from '@supabase/supabase-js';

// Initialize Supabase Admin Client using the service_role key
const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
  { auth: { persistSession: false } }
);

test.describe('Security Hardening Verification', () => {
  const createdUserIds: string[] = [];

  // Helper to create a pre-confirmed user and log them in
  async function createAndLoginUser(page, email: string) {
    const password = 'TestPassword123!';
    
    // Create pre-confirmed user via Admin Auth API (bypasses signup rate limits and confirmation emails)
    const { data, error } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true
    });

    if (error || !data?.user) {
      throw new Error(`Failed to create test user: ${error?.message}`);
    }

    createdUserIds.push(data.user.id);

    // Log in via UI
    await page.goto('/login');
    await page.fill('#email', email);
    await page.fill('#password', password);
    await page.click('button[type="submit"]');

    // Wait for redirect to dashboard
    await expect(page.locator('h1.desk-title')).toHaveText("Investigator's Desk", { timeout: 15000 });
    return data.user;
  }

  // Teardown created users to keep the database clean
  test.afterAll(async () => {
    for (const userId of createdUserIds) {
      await supabaseAdmin.auth.admin.deleteUser(userId).catch(err => {
        console.error(`Failed to cleanup user ${userId}:`, err);
      });
    }
  });

  // 1. Verify HTTP Security Headers
  test('HTTP Security Headers are correctly set', async ({ request }) => {
    const response = await request.get('/');
    const headers = response.headers();

    expect(headers['content-security-policy']).toContain("default-src 'self'");
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    expect(headers['permissions-policy']).toBe('camera=(), microphone=(), geolocation=()');
  });

  // 2. Verify target script rendering (inert text, not executed)
  test('Submit script tag target and verify it renders inert', async ({ page }) => {
    // Fail test if any alert dialog is displayed (XSS proof)
    page.on('dialog', async (dialog) => {
      dialog.dismiss();
      throw new Error(`XSS vulnerability: dialog alert triggered with message: ${dialog.message()}`);
    });

    const email = `xss-test-${Date.now()}@example.com`;
    await createAndLoginUser(page, email);

    // Go to New Case page
    await page.click('#new-investigation-btn');
    await expect(page).toHaveURL(/.*\/new/);

    // Enter target containing script tags
    const xssTarget = '<script>alert(1)</script>';
    await page.fill('#target-input', xssTarget);
    await page.click('#open-case-submit-btn');

    // Wait for redirect to case page
    await expect(page).toHaveURL(/.*\/cases\/.+/, { timeout: 15000 });

    // Wait for client-side load of the target on the case page
    const targetElement = page.locator('.detail-target');
    await expect(targetElement).toBeVisible({ timeout: 15000 });
    await expect(targetElement).toHaveText(xssTarget);
  });

  // 3. Verify Rate Limiting for real (6th request gets 429)
  test('Hit rate limit (6th request in a minute gets 429)', async ({ page, request }) => {
    const email = `rate-limit-${Date.now()}@example.com`;
    await createAndLoginUser(page, email);

    // Get the session cookies from the page to use with direct API requests
    const cookies = await page.context().cookies();
    const cookieString = cookies.map(c => `${c.name}=${c.value}`).join('; ');

    // Send 5 successful API calls, then verify the 6th gets 429
    for (let i = 1; i <= 6; i++) {
      const res = await request.post('/api/investigations', {
        headers: {
          'Cookie': cookieString,
          'Content-Type': 'application/json',
        },
        data: {
          target: `1.1.1.${i}`,
          investigationType: 'ioc',
        }
      });

      if (i <= 5) {
        expect(res.status()).toBe(202);
      } else {
        expect(res.status()).toBe(429);
        const json = await res.json();
        expect(json.error).toContain('Rate limit exceeded');
      }
    }
  });

  // 4. Verify Cross-user Case Isolation (Defense-in-depth + RLS)
  test('Attempt to load another user\'s case directly', async ({ browser }) => {
    const emailA = `user-a-${Date.now()}@example.com`;
    const emailB = `user-b-${Date.now()}@example.com`;

    // Context A: Create case
    const contextA = await browser.newContext();
    const pageA = await contextA.newPage();
    await createAndLoginUser(pageA, emailA);

    await pageA.click('#new-investigation-btn');
    await pageA.fill('#target-input', '8.8.8.8');
    await pageA.click('#open-case-submit-btn');
    await expect(pageA).toHaveURL(/.*\/cases\/.+/, { timeout: 15000 });

    const caseUrl = pageA.url();
    const caseId = caseUrl.split('/').pop();
    expect(caseId).toBeTruthy();

    // Context B: Try to access User A's case
    const contextB = await browser.newContext();
    const pageB = await contextB.newPage();
    await createAndLoginUser(pageB, emailB);

    // Verify API returns 404 Not Found for User B trying to access User A's case
    const cookiesB = await contextB.cookies();
    const cookieStringB = cookiesB.map(c => `${c.name}=${c.value}`).join('; ');

    const apiRes = await contextB.request.get(`/api/investigations/${caseId}`, {
      headers: {
        'Cookie': cookieStringB
      }
    });
    
    expect(apiRes.status()).toBe(404);

    await contextA.close();
    await contextB.close();
  });
});
