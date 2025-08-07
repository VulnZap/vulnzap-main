import chalk from 'chalk';
import { getUserProfile, UserProfile } from '../api/apis.js';

// Typography system (matching CLI design)
const typography = {
  title: (text: string) => chalk.white.bold(text),
  subtitle: (text: string) => chalk.gray(text),
  success: (text: string) => chalk.green(text),
  warning: (text: string) => chalk.yellow(text),
  error: (text: string) => chalk.red(text),
  info: (text: string) => chalk.blue(text),
  muted: (text: string) => chalk.gray.dim(text),
  accent: (text: string) => chalk.cyan(text),
  code: (text: string) => chalk.gray.bgBlack(` ${text} `),
};

// Spacing helpers
const spacing = {
  line: () => console.log(''),
  section: () => console.log('\n'),
  block: () => console.log('\n\n'),
};

export function getTierDisplay(tier: string): string {
  switch (tier.toLowerCase()) {
    case 'free':
      return typography.muted('Free');
    case 'pro':
      return typography.accent('Pro');
    case 'enterprise':
      return typography.success('Enterprise');
    default:
      return typography.muted(tier);
  }
}

export function getUsageDisplay(current: number, limit: number, period: string): { display: string; shouldShowFomo: boolean } {
  const percentage = (current / limit) * 100;
  const remaining = limit - current;
  
  let display: string;
  let shouldShowFomo = false;

  if (percentage >= 90) {
    display = typography.error(`${remaining} scans remaining this ${period}`);
    shouldShowFomo = true;
  } else if (percentage >= 75) {
    display = typography.warning(`${remaining} scans remaining this ${period}`);
    shouldShowFomo = true;
  } else if (percentage >= 50) {
    display = typography.accent(`${remaining} scans remaining this ${period}`);
  } else {
    display = typography.muted(`${remaining} scans remaining this ${period}`);
  }

  return { display, shouldShowFomo };
}

export function getFomoMessage(tier: string, current: number, limit: number): string | null {
  const percentage = (current / limit) * 100;
  
  if (tier.toLowerCase() === 'free') {
    if (percentage >= 90) {
      return typography.warning('Upgrade to Pro for unlimited scans and advanced features');
    } else if (percentage >= 75) {
      return typography.muted('Consider upgrading to Pro to avoid hitting limits');
    }
  }
  
  return null;
}

export async function displayUserWelcome(): Promise<void> {
  try {
    const profile = await getUserProfile();
    
    if (!profile) {
      // No profile available, skip personalized greeting
      return;
    }

    spacing.line();
    
    // Welcome message
    const firstName = profile.username;
    console.log(typography.subtitle(`Good to see you here, ${firstName}`));
    
    // Tier and usage in a clean line
    const tierDisplay = getTierDisplay(profile.subscription.tier);
    const { display: usageDisplay, shouldShowFomo } = getUsageDisplay(
      profile.apiUsage.lineScans,
      profile.subscription.line_scans_limit,
      'month'
    );
    
    console.log(`${tierDisplay} • ${usageDisplay}`);
    
    // FOMO message if needed
    if (shouldShowFomo) {
      const fomoMessage = getFomoMessage(profile.subscription.tier, profile.apiUsage.lineScans, profile.subscription.line_scans_limit);
      if (fomoMessage) {
        spacing.line();
        console.log(fomoMessage);
      }
    }

    spacing.line();
    
  } catch (error) {
    // Silently fail - don't interrupt the user flow if profile fetch fails
    return;
  }
}

export async function displayUserStatus(): Promise<void> {
  try {
    const profile = await getUserProfile();
    
    if (!profile) {
      console.log(typography.muted('Profile information not available'));
      return;
    }

    console.log(typography.info('Account Information'));
    spacing.line();
    
    console.log(typography.muted(`  Name: ${profile.username}`));
    console.log(typography.muted(`  Email: ${profile.email}`));
    console.log(typography.muted(`  Tier: ${profile.subscription.tier.charAt(0).toUpperCase() + profile.subscription.tier.slice(1)}`));
    
    spacing.line();
    console.log(typography.info('Usage This Month'));
    spacing.line();
    
    const percentage = Math.round((profile.apiUsage.lineScans / profile.subscription.line_scans_limit) * 100);
    const remaining = profile.subscription.line_scans_limit - profile.apiUsage.lineScans;
    
    console.log(typography.muted(`  Scans used: ${profile.apiUsage.lineScans} of ${profile.subscription.line_scans_limit} (${percentage}%)`));
    console.log(typography.muted(`  Remaining: ${remaining} scans`));
    
    // Progress bar
    const barLength = 20;
    const filledLength = Math.round((profile.apiUsage.lineScans / profile.subscription.line_scans_limit) * barLength);
    const bar = '█'.repeat(filledLength) + '░'.repeat(barLength - filledLength);
    
    let barColor;
    if (percentage >= 90) barColor = chalk.red;
    else if (percentage >= 75) barColor = chalk.yellow;
    else if (percentage >= 50) barColor = chalk.cyan;
    else barColor = chalk.green;
    
    console.log(typography.muted(`  Progress: ${barColor(bar)} ${percentage}%`));
    
    // FOMO message
    const fomoMessage = getFomoMessage(profile.subscription.tier, profile.apiUsage.lineScans, profile.subscription.line_scans_limit);
    if (fomoMessage) {
      spacing.section();
      console.log(fomoMessage);
      if (profile.subscription.tier.toLowerCase() === 'free') {
        console.log(typography.muted('Visit vulnzap.com/pricing to upgrade'));
      }
    }
    
  } catch (error) {
    console.log(typography.muted('Profile information not available'));
  }
} 