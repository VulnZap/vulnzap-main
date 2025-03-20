"use client";

import Link from "next/link";
import { Button } from "@/components/ui/button";
import { ChevronRight, Shield, Code, Zap } from "lucide-react";

export function Hero() {
  return (
    <div className="relative isolate pt-24 pb-16">
      <div className="absolute inset-x-0 top-28 -z-10 transform-gpu overflow-hidden blur-3xl" aria-hidden="true">
        <div
          className="relative left-[calc(50%-11rem)] aspect-[1155/678] w-[36.125rem] -translate-x-1/2 rotate-[30deg] bg-gradient-to-tr from-primary to-secondary opacity-20 sm:left-[calc(50%-30rem)] sm:w-[72.1875rem]"
          style={{
            clipPath:
              'polygon(74.1% 44.1%, 100% 61.6%, 97.5% 26.9%, 85.5% 0.1%, 80.7% 2%, 72.5% 32.5%, 60.2% 62.4%, 52.4% 68.1%, 47.5% 58.3%, 45.2% 34.5%, 27.5% 76.7%, 0.1% 64.9%, 17.9% 100%, 27.6% 76.8%, 76.1% 97.7%, 74.1% 44.1%)',
          }}
        />
      </div>
      
      <div className="mx-auto max-w-7xl px-6 lg:px-8">
        <div className="mx-auto max-w-3xl text-center">
          <h1 className="text-4xl font-bold tracking-tight sm:text-6xl">
            Secure Your Code With <span className="text-primary">Intelligent</span> Vulnerability Scanning
          </h1>
          <p className="mt-6 text-lg leading-8 text-muted-foreground">
            VulnZap analyzes your dependencies across multiple programming ecosystems, 
            identifies vulnerabilities, and provides actionable remediation advice.
          </p>
          <div className="mt-10 flex items-center justify-center gap-x-6">
            <Button asChild size="lg" className="gap-1">
              <Link href="#get-started">
                Get Started <ChevronRight className="h-4 w-4" />
              </Link>
            </Button>
            <Button variant="outline" asChild size="lg">
              <Link href="#docs">Documentation</Link>
            </Button>
          </div>
        </div>
        
        <div className="mt-16 flow-root sm:mt-20">
          <div className="rounded-xl bg-card p-2 ring-1 ring-ring/10 lg:rounded-2xl">
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-3 p-6">
              <div className="flex flex-col items-center gap-2 rounded-lg p-4 bg-background shadow-sm">
                <Shield className="h-10 w-10 text-primary" />
                <h3 className="text-lg font-semibold">Multiple Ecosystems</h3>
                <p className="text-center text-sm text-muted-foreground">
                  Supports npm, pip, Go, and more programming language ecosystems
                </p>
              </div>
              <div className="flex flex-col items-center gap-2 rounded-lg p-4 bg-background shadow-sm">
                <Code className="h-10 w-10 text-primary" />
                <h3 className="text-lg font-semibold">Actionable Reports</h3>
                <p className="text-center text-sm text-muted-foreground">
                  Detailed vulnerability reports with severity ratings and fix recommendations
                </p>
              </div>
              <div className="flex flex-col items-center gap-2 rounded-lg p-4 bg-background shadow-sm">
                <Zap className="h-10 w-10 text-primary" />
                <h3 className="text-lg font-semibold">LLM Integration</h3>
                <p className="text-center text-sm text-muted-foreground">
                  Seamless integration with your LLM via Model Context Protocol
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
} 