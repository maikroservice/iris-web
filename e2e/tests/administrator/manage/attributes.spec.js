import { test, expect } from '@playwright/test';

test.beforeEach(async({ page }) => {
    await page.goto('/manage/attributes');
});

test('should render task custom attributes (issue #798)', async ({ page }) => {
    await page.getByRole('link', { name: 'Tasks', exact: true }).click();

    const attributeDefinition = {
        'CustomAttributeTab': {
            'CustomAttributeField': {
                'type': 'input_string',
                'mandatory': false,
                'value': ''
            }
        }
    };
    await page.getByRole('textbox').focus();
    await page.keyboard.press('ControlOrMeta+a');
    await page.keyboard.press('Delete');
    await page.keyboard.type(JSON.stringify(attributeDefinition));

    await page.getByRole('button', { name: 'Preview' }).click();
    await page.getByRole('tab', { name: 'CustomAttributeTab' }).click();
    await expect(page.getByText('CustomAttributeField', { exact: true })).toBeVisible();
});
