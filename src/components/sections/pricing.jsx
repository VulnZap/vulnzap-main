'use client';

import { Check } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import Link from 'next/link';

const tiers = [
  {
    name: 'Free',
    id: 'free',
    price: '0',
    description:
      'Get started with basic vulnerability scanning for small personal projects.',
    features: [
      'npm and pip ecosystem support',
      'GitHub Advisory Database',
      'Basic vulnerability reports',
      'Up to 5 projects',
      'Community support',
    ],
    cta: 'Start Free',
    href: '#get-started',
    popular: false,
  },
  {
    name: 'Pro',
    id: 'pro',
    price: '49',
    description:
      'Enhanced scanning with premium features for professional developers and teams.',
    features: [
      'All ecosystems supported',
      'GitHub Advisory + NVD integration',
      'Detailed vulnerability reports',
      'Remediation advice',
      'Up to 20 projects',
      'CI/CD integration',
      'Email support',
    ],
    cta: 'Upgrade to Pro',
    href: '#get-started',
    popular: true,
  },
  {
    name: 'Enterprise',
    id: 'enterprise',
    price: '199',
    description:
      'Comprehensive vulnerability management solution for organizations with advanced security needs.',
    features: [
      'All Pro features',
      'Unlimited projects',
      'Custom vulnerability database',
      'Advanced analytics',
      'SLA guarantee',
      'Security policy integration',
      'Private vulnerability database',
      'Dedicated support',
    ],
    cta: 'Contact Sales',
    href: '#contact',
    popular: false,
  },
];

export function Pricing() {
  return (
    <section id='pricing' className='py-24'>
      <div className='px-6 mx-auto max-w-7xl lg:px-8'>
        <div className='max-w-3xl mx-auto space-y-4 text-center'>
          <h2 className='text-3xl font-bold tracking-tight sm:text-4xl'>
            Simple, Transparent Pricing
          </h2>
          <p className='text-lg text-muted-foreground'>
            Choose the plan that fits your needs. All plans include access to
            our core vulnerability scanning engine.
          </p>
        </div>

        <div className='grid items-start grid-cols-1 gap-8 mt-16 sm:grid-cols-2 lg:grid-cols-3'>
          {tiers.map((tier) => (
            <Card
              key={tier.id}
              className={`flex flex-col h-full ${
                tier.popular ? 'ring-2 ring-primary relative' : ''
              }`}
            >
              {tier.popular && (
                <Badge className='absolute px-3 py-1 -top-2 -right-2'>
                  Most Popular
                </Badge>
              )}
              <CardHeader className='pb-8'>
                <CardTitle className='text-2xl'>{tier.name}</CardTitle>
                <div className='flex items-baseline mt-4 text-6xl font-extrabold'>
                  ${tier.price}
                  <span className='ml-1 text-2xl font-medium text-muted-foreground'>
                    /mo
                  </span>
                </div>
                <CardDescription className='mt-5 text-sm text-muted-foreground'>
                  {tier.description}
                </CardDescription>
              </CardHeader>
              <CardContent className='flex-grow'>
                <ul className='space-y-3'>
                  {tier.features.map((feature) => (
                    <li key={feature} className='flex items-start'>
                      <div className='flex-shrink-0'>
                        <Check className='w-5 h-5 text-primary' />
                      </div>
                      <p className='ml-3 text-sm text-foreground'>{feature}</p>
                    </li>
                  ))}
                </ul>
              </CardContent>
              <CardFooter>
                <Button
                  asChild
                  className='w-full'
                  variant={tier.popular ? 'default' : 'outline'}
                >
                  <Link href={tier.href}>{tier.cta}</Link>
                </Button>
              </CardFooter>
            </Card>
          ))}
        </div>

        <div className='mt-12 text-center'>
          <p className='text-sm text-muted-foreground'>
            Need a custom plan?{' '}
            <Link
              href='#contact'
              className='font-medium text-primary hover:underline'
            >
              Contact us
            </Link>{' '}
            for custom pricing options.
          </p>
        </div>
      </div>
    </section>
  );
}
