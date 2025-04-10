'use client';

import Image from 'next/image';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Check,
  ShieldCheck,
  GitBranch,
  RefreshCcw,
  Puzzle,
} from 'lucide-react';

export function Features() {
  return (
    <section id='features' className='py-24 space-y-8'>
      <div className='max-w-3xl px-6 mx-auto space-y-4 text-center lg:px-8'>
        <h2 className='text-3xl font-bold tracking-tight sm:text-4xl'>
          Powerful Features
        </h2>
        <p className='text-lg text-muted-foreground'>
          VulnZap provides comprehensive vulnerability scanning for multiple
          ecosystems with actionable insights.
        </p>
      </div>

      <div className='px-6 pt-8 mx-auto max-w-7xl lg:px-8'>
        <Tabs defaultValue='scanning' className='w-full'>
          <div className='flex justify-center mb-8'>
            <TabsList className='grid w-full max-w-2xl grid-cols-4'>
              <TabsTrigger value='scanning'>Scanning</TabsTrigger>
              <TabsTrigger value='ecosystems'>Ecosystems</TabsTrigger>
              <TabsTrigger value='integration'>Integration</TabsTrigger>
              <TabsTrigger value='reports'>Reports</TabsTrigger>
            </TabsList>
          </div>

          <TabsContent value='scanning' className='space-y-4'>
            <div className='grid items-center grid-cols-1 gap-8 lg:grid-cols-2'>
              <div className='space-y-6'>
                <Card>
                  <CardHeader>
                    <CardTitle className='flex items-center gap-2'>
                      <ShieldCheck className='w-5 h-5 text-primary' />
                      Multiple Vulnerability Databases
                    </CardTitle>
                    <CardDescription>
                      VulnZap leverages both the GitHub Advisory Database and
                      National Vulnerability Database (NVD) for comprehensive
                      scanning.
                    </CardDescription>
                  </CardHeader>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className='flex items-center gap-2'>
                      <RefreshCcw className='w-5 h-5 text-primary' />
                      Intelligent Caching
                    </CardTitle>
                    <CardDescription>
                      Smart caching mechanism minimizes API calls and ensures
                      efficient vulnerability checks.
                    </CardDescription>
                  </CardHeader>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className='flex items-center gap-2'>
                      <GitBranch className='w-5 h-5 text-primary' />
                      Version Matching
                    </CardTitle>
                    <CardDescription>
                      Advanced version comparison algorithm ensures accurate
                      vulnerability detection for your specific dependency
                      versions.
                    </CardDescription>
                  </CardHeader>
                </Card>
              </div>
              <div className='relative h-[400px] rounded-lg bg-muted p-2'>
                <div className='absolute inset-0 flex items-center justify-center text-muted-foreground'>
                  [Scanning visualization placeholder]
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value='ecosystems' className='space-y-4'>
            <div className='grid items-center grid-cols-1 gap-8 lg:grid-cols-2'>
              <div className='relative h-[400px] rounded-lg bg-muted p-2'>
                <div className='absolute inset-0 flex items-center justify-center text-muted-foreground'>
                  [Ecosystems visualization placeholder]
                </div>
              </div>
              <div className='space-y-4'>
                <h3 className='text-2xl font-bold'>Supported Ecosystems</h3>
                <p className='mb-6 text-muted-foreground'>
                  VulnZap supports multiple programming ecosystems, ensuring
                  comprehensive coverage for your projects.
                </p>
                <ul className='space-y-3'>
                  {[
                    'npm (JavaScript/TypeScript)',
                    'pip (Python)',
                    'Go modules',
                    'Cargo (Rust)',
                    'Maven (Java)',
                    'NuGet (.NET)',
                    'Composer (PHP)',
                  ].map((eco) => (
                    <li key={eco} className='flex items-center gap-2'>
                      <div className='p-1 rounded-full bg-primary/10'>
                        <Check className='w-5 h-5 text-primary' />
                      </div>
                      <span>{eco}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </TabsContent>

          <TabsContent value='integration' className='space-y-4'>
            <div className='grid items-center grid-cols-1 gap-8 lg:grid-cols-2'>
              <div className='space-y-6'>
                <Card>
                  <CardHeader>
                    <CardTitle className='flex items-center gap-2'>
                      <Puzzle className='w-5 h-5 text-primary' />
                      Model Context Protocol
                    </CardTitle>
                    <CardDescription>
                      Seamlessly integrates with your LLM through the Model
                      Context Protocol (MCP), providing actionable security
                      insights.
                    </CardDescription>
                  </CardHeader>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className='flex items-center gap-2'>
                      <RefreshCcw className='w-5 h-5 text-primary' />
                      REST API
                    </CardTitle>
                    <CardDescription>
                      Comprehensive REST API for integration with your existing
                      tools and workflows.
                    </CardDescription>
                  </CardHeader>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className='flex items-center gap-2'>
                      <GitBranch className='w-5 h-5 text-primary' />
                      CLI Tool
                    </CardTitle>
                    <CardDescription>
                      Command-line interface for easy integration into your
                      CI/CD pipelines.
                    </CardDescription>
                  </CardHeader>
                </Card>
              </div>
              <div className='relative h-[400px] rounded-lg bg-muted p-2'>
                <div className='absolute inset-0 flex items-center justify-center text-muted-foreground'>
                  [Integration visualization placeholder]
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value='reports' className='space-y-4'>
            <div className='grid items-center grid-cols-1 gap-8 lg:grid-cols-2'>
              <div className='relative h-[400px] rounded-lg bg-muted p-2'>
                <div className='absolute inset-0 flex items-center justify-center text-muted-foreground'>
                  [Reports visualization placeholder]
                </div>
              </div>
              <div className='space-y-6'>
                <Card>
                  <CardHeader>
                    <CardTitle className='flex items-center gap-2'>
                      <ShieldCheck className='w-5 h-5 text-primary' />
                      Detailed Vulnerability Reports
                    </CardTitle>
                    <CardDescription>
                      Comprehensive reports with CVSS scores, affected versions,
                      and detailed descriptions.
                    </CardDescription>
                  </CardHeader>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className='flex items-center gap-2'>
                      <RefreshCcw className='w-5 h-5 text-primary' />
                      Remediation Advice
                    </CardTitle>
                    <CardDescription>
                      Actionable recommendations for fixing or mitigating
                      discovered vulnerabilities.
                    </CardDescription>
                  </CardHeader>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className='flex items-center gap-2'>
                      <GitBranch className='w-5 h-5 text-primary' />
                      Export Options
                    </CardTitle>
                    <CardDescription>
                      Export reports in multiple formats, including JSON, CSV,
                      and PDF for easy sharing.
                    </CardDescription>
                  </CardHeader>
                </Card>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </section>
  );
}
