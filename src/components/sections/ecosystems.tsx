"use client";

import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const ecosystems = [
  {
    name: "JavaScript/TypeScript",
    icon: "npm",
    description: "Scan npm packages for known vulnerabilities and receive detailed remediation advice.",
    package: "package.json",
    style: "bg-yellow-600",
    features: ["Lockfile analysis", "Direct dependencies", "Transitive dependencies"]
  },
  {
    name: "Python",
    icon: "python",
    description: "Detect vulnerabilities in pip packages across your Python projects.",
    package: "requirements.txt",
    style: "bg-blue-600",
    features: ["Poetry support", "Virtual environments", "PyPI security advisories"]
  },
  {
    name: "Go",
    icon: "go",
    description: "Identify security issues in Go modules and get actionable insights.",
    package: "go.mod",
    style: "bg-cyan-600",
    features: ["Version analysis", "GOPROXY support", "Build tag considerations"]
  },
  {
    name: "Rust",
    icon: "rust",
    description: "Find vulnerabilities in Cargo packages with detailed severity information.",
    package: "Cargo.toml",
    style: "bg-orange-700",
    features: ["RustSec advisories", "Crates.io integration", "Build profiles"]
  },
  {
    name: "Java",
    icon: "java",
    description: "Scan Maven dependencies for CVEs and other security vulnerabilities.",
    package: "pom.xml",
    style: "bg-red-700",
    features: ["Maven Central scans", "Gradle support", "Spring vulnerabilities"]
  },
  {
    name: ".NET",
    icon: "dotnet",
    description: "Check NuGet packages for security issues and get remediation steps.",
    package: ".csproj / .fsproj",
    style: "bg-purple-700",
    features: ["Multiple project formats", "Framework targeting", "GitHub security advisories"]
  }
];

export function Ecosystems() {
  return (
    <section id="ecosystems" className="py-24 bg-muted/50">
      <div className="mx-auto max-w-7xl px-6 lg:px-8">
        <div className="text-center space-y-4 max-w-3xl mx-auto">
          <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">Supported Ecosystems</h2>
          <p className="text-lg text-muted-foreground">
            VulnZap provides comprehensive vulnerability scanning across multiple programming ecosystems.
          </p>
        </div>

        <div className="mt-16 grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-3">
          {ecosystems.map((eco) => (
            <Card key={eco.name} className="overflow-hidden">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-3">
                  <Avatar className={eco.style}>
                    <AvatarImage src={`/icons/${eco.icon}.svg`} alt={eco.name} />
                    <AvatarFallback className="text-white font-medium">{eco.name.substring(0, 2)}</AvatarFallback>
                  </Avatar>
                  <div>
                    <CardTitle>{eco.name}</CardTitle>
                    <CardDescription className="text-xs mt-1">
                      {eco.package}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">{eco.description}</p>
                <div className="mt-4 flex flex-wrap gap-2">
                  {eco.features.map((feature) => (
                    <Badge key={feature} variant="outline" className="text-xs">
                      {feature}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
} 