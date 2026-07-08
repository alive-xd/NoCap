import { test, expect } from '@playwright/test';

test.describe('Investigation End-to-End', () => {
  test('Complete investigation flow', async ({ page }) => {
    const email = process.env.PLAYWRIGHT_TEST_EMAIL;
    const password = process.env.PLAYWRIGHT_TEST_PASSWORD;

    if (!email || !password) {
      throw new Error(
        'PLAYWRIGHT_TEST_EMAIL and PLAYWRIGHT_TEST_PASSWORD must be set in .env.test.local'
      );
    }

    // 1. Go to the login page directly (or via landing)
    await page.goto('/login');

    // 2. Log in
    await page.fill('#email', email);
    await page.fill('#password', password);
    await page.click('button[type="submit"]');

    // 3. Wait for navigation to dashboard
    await expect(page.locator('h1.desk-title')).toHaveText("Investigator's Desk", { timeout: 10000 });

    // 4. Submit a new investigation
    await page.click('#new-investigation-btn');
    
    // We expect navigation to /new
    await expect(page).toHaveURL(/.*\/new/);

    // Fill out the target (example.com is benign and safe)
    await page.fill('#target-input', 'example.com');
    // Assuming there is a submit button in the new investigation form
    await page.click('#open-case-submit-btn');

    // 5. Wait for the redirect to the case detail page: /cases/[id]
    await expect(page).toHaveURL(/.*\/cases\/.+/, { timeout: 15000 });

    // Wait for status to reach Completed
    // The case page will initially show a status like FETCHING_ARTIFACTS or SCORING, then COMPLETED.
    // Use a generous timeout (e.g. 60s) since it hits real APIs (AbuseIPDB, VirusTotal, etc.)
    await expect(page.locator('.status-pill')).toContainText('Completed', { timeout: 60000 });

    // 7. Click a finding
    // The findings list usually has a class or element we can click. We'll look for the first finding row.
    const findingRow = page.locator('.finding-card').first();
    await expect(findingRow).toBeVisible();
    await findingRow.click();

    // 8. Click "View Raw Artifact" and assert JSON renders
    // We assume the artifact view button has text "View Raw Artifact" or similar.
    const viewArtifactBtn = page.locator('text=View Raw Artifact').first();
    await viewArtifactBtn.click();
    
    // Check that a JSON block is rendered (e.g., inside a <pre> tag in a modal or section)
    const jsonPre = page.locator('pre').first();
    await expect(jsonPre).toBeVisible();
    const jsonContent = await jsonPre.textContent();
    expect(jsonContent).toBeTruthy();
    // Validate it's valid JSON
    expect(() => JSON.parse(jsonContent as string)).not.toThrow();

    // 9. Navigate to /analyzers and assert the Analyzer Library page renders
    await page.goto('/analyzers');
    await expect(page.locator('h1')).toContainText('Analyzer Library');
    // Assert that some documented analyzers render
    await expect(page.locator('text=ASNReputationAnalyzer')).toBeVisible();
  });
});
