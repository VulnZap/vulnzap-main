import { typography, layout } from './typography.js';
import chalk from 'chalk';

/**
 * Magic Auth - Premium authentication experience
 * Creates a beautiful, animated waiting state while the user authenticates in browser
 */
export async function displayMagicAuth() {
    layout.clear();
    layout.section();

    // Header
    console.log(typography.header('  ✨ Magic Auth'));
    console.log(typography.dim('  Secure browser-based authentication'));
    layout.section();

    // Visual connection indicator
    console.log(typography.dim('  ┌─────────────────────────────────────┐'));
    console.log(typography.dim('  │                                     │'));
    console.log(typography.accent('  │        Opening your browser...      │'));
    console.log(typography.dim('  │                                     │'));
    console.log(typography.dim('  └─────────────────────────────────────┘'));
    layout.spacer();

    // Instructions
    console.log(typography.body('  Please complete authentication in your browser.'));
    console.log(typography.dim('  The window should open automatically.'));
    layout.section();
}

/**
 * Display waiting state with animation
 */
export function displayAuthWaiting() {
    console.log(typography.dim('  Waiting for authentication...'));
    console.log(typography.dim('  (Press Ctrl+C to cancel)'));
    layout.spacer();
}

/**
 * Display successful authentication
 */
export function displayAuthSuccess(username?: string) {
    layout.clear();
    layout.section();

    // Success animation
    console.log(typography.success('  ✓ Authentication Successful'));
    layout.spacer();

    if (username) {
        console.log(typography.header(`  Welcome back, ${username}!`));
    }

    layout.section();
}

/**
 * Display authentication error with recovery options
 */
export function displayAuthError(errorMessage?: string) {
    layout.clear();
    layout.section();

    console.log(typography.error('  ✗ Authentication Failed'));
    layout.spacer();

    if (errorMessage) {
        console.log(typography.dim(`  ${errorMessage}`));
        layout.spacer();
    }

    console.log(typography.accent('  Recovery Options:'));
    console.log(typography.dim('  1. Try again with: vulnzap init'));
    console.log(typography.dim('  2. Manual setup: vulnzap setup -k <api-key>'));
    console.log(typography.dim('  3. Get help: vulnzap.com/support'));

    layout.section();
}
