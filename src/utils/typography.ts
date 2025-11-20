import chalk from 'chalk';

// Design Tokens
const COLORS = {
    primary: '#FFFFFF',    // Pure White
    secondary: '#888888',  // Neutral Gray
    accent: '#007AFF',     // Apple Blue
    success: '#34C759',    // Apple Green
    warning: '#FF9500',    // Apple Orange
    error: '#FF3B30',      // Apple Red
    bg: '#000000',         // Pure Black
};

// Typography System
export const typography = {
    // Headers
    header: (text: string) => chalk.hex(COLORS.primary).bold(text),
    subheader: (text: string) => chalk.hex(COLORS.secondary)(text),

    // Body
    body: (text: string) => chalk.hex(COLORS.secondary)(text),
    strong: (text: string) => chalk.hex(COLORS.primary)(text),

    // Status
    success: (text: string) => chalk.hex(COLORS.success)(text),
    warning: (text: string) => chalk.hex(COLORS.warning)(text),
    error: (text: string) => chalk.hex(COLORS.error)(text),
    accent: (text: string) => chalk.hex(COLORS.accent)(text),

    // Elements
    code: (text: string) => chalk.bgHex('#1C1C1E').hex(COLORS.secondary)(` ${text} `),
    link: (text: string) => chalk.underline.hex(COLORS.secondary)(text),
    dim: (text: string) => chalk.hex('#444444')(text),
};

// Layout Engine
export const layout = {
    // Clear screen "Cinema Mode"
    clear: () => {
        process.stdout.write('\x1Bc');
    },

    // Spacing
    spacer: () => console.log(''),
    section: () => console.log('\n\n'),

    // Components
    banner: (version: string) => {
        layout.clear();
        layout.spacer();
        console.log(typography.header('  VulnZap'));
        console.log(typography.subheader(`  Security-first AI development v${version}`));
        layout.section();
    },

    step: (number: number, total: number, title: string) => {
        console.log(typography.dim(`  Step ${number} of ${total}`));
        console.log(typography.header(`  ${title}`));
        layout.spacer();
    }
};
